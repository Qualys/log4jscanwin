#include "stdafx.h"
#include "Utils.h"

#include "zlib/zlib.h"
#include "minizip/unzip.h"
#include "minizip/iowin32.h"


constexpr wchar_t* qualys_program_data_location = L"%ProgramData%\\Qualys";
constexpr wchar_t* report_sig_output_file = L"log4j_findings.out";
constexpr wchar_t* report_sig_summary_file = L"log4j_summary.out";
constexpr wchar_t* report_sig_status_file = L"status.txt";

constexpr wchar_t* remediation_report_file = L"log4j_remediate.out";
constexpr wchar_t* remediation_status_file = L"remediation_status.out";


FILE* status_file = nullptr;
std::vector<std::wstring> error_array;


std::wstring A2W(const std::string& str) {
  int length_wide = MultiByteToWideChar(CP_ACP, 0, str.data(), -1, NULL, 0);
  wchar_t *string_wide = static_cast<wchar_t*>(_alloca((length_wide * sizeof(wchar_t)) + sizeof(wchar_t)));
  MultiByteToWideChar(CP_ACP, 0, str.data(), -1, string_wide, length_wide);
  std::wstring result(string_wide, length_wide - 1);
  return result;
}

std::string W2A(const std::wstring& str) {
  int length_ansi = WideCharToMultiByte(CP_ACP, 0, str.data(), -1, NULL, 0, NULL, NULL);
  char* string_ansi = static_cast<char*>(_alloca(length_ansi + sizeof(char)));
  WideCharToMultiByte(CP_ACP, 0, str.data(), -1, string_ansi, length_ansi, NULL, NULL);
  std::string result(string_ansi, length_ansi - 1);
  return result;
}

std::wstring GetTempFilePath(const std::wstring &prefix) {
  std::vector<wchar_t> tmp_path(_MAX_PATH + 1, L'\0');
  std::vector<wchar_t> tmp_filename(_MAX_PATH + 1, L'\0');

  if (GetTempPath(static_cast<DWORD>(tmp_path.size()), tmp_path.data()) != 0 && 
    GetTempFileName(tmp_path.data(), prefix.c_str(), 0, tmp_filename.data()) != 0) {
    return tmp_filename.data();
  } 

  return L"";
}

bool StartsWithCaseInsensitive(const std::wstring& text, const std::wstring& prefix) {
  return (prefix.empty() ||
    (text.size() >= prefix.size() &&
      std::mismatch(text.begin(), text.end(), prefix.begin(), prefix.end(),
        [](wchar_t first_char, wchar_t second_char) {
          return first_char == second_char || towlower(first_char) == towlower(second_char);
        }).second == prefix.end()));
}

void SplitWideString(std::wstring str, const std::wstring& token, std::vector<std::wstring>& result) {
  while (str.size()) {
    auto index = str.find(token);
    if (index != std::wstring::npos) {
      result.push_back(str.substr(0, index));
      str = str.substr(index + token.size());      
    }
    else {
      result.push_back(str);
      str.clear();
    }
  }
}

bool SanitizeContents(std::string& str) {
  auto iter = str.begin();
  while (iter != str.end()) {
    if (*iter == '\r') {
      iter = str.erase(iter);
    } else {
      ++iter;
    }
  }
  return true;
}

bool StripWhitespace(std::string& str) {
  while (1) {
    if (str.length() == 0) break;
    if (!isascii(str[0])) break;
    if (!isspace(str[0])) break;
    str.erase(0, 1);
  }

  int n = (int)str.length();
  while (n > 0) {
    if (!isascii(str[n - 1])) break;
    if (!isspace(str[n - 1])) break;
    n--;
  }
  str.erase(n, str.length() - n);
  return true;
}

bool GetDictionaryValue(std::string& dict, std::string name,
                        std::string defaultValue, std::string& value) {
  if (std::string::npos != dict.find(name.c_str(), 0)) {
    size_t pos = dict.find(name.c_str(), 0);
    size_t eol = dict.find("\n", pos);
    value = dict.substr(pos + name.size(), eol - (pos + name.size()));
    return true;
  }
  value = defaultValue;
  return false;
}

bool ExpandEnvironmentVariables(const wchar_t* source, std::wstring& destination) {
  try {
    DWORD dwReserve = ExpandEnvironmentStrings(source, nullptr, 0);
    if (dwReserve == 0) {
      return false;
    }
    destination.resize(dwReserve);
    DWORD dwWritten = ExpandEnvironmentStrings(source, &destination[0],
                                               (DWORD)destination.size());
    if (dwWritten == 0) {
      return false;
    }
    // dwWritten includes the null terminating character
    destination.resize(dwWritten - 1);
  } catch (std::bad_alloc&) {
    return false;
  }
  return true;
}

bool DirectoryExists(std::wstring directory) {
  if (directory.empty()) {
    return false;
  }
  DWORD fileAttr = GetFileAttributes(directory.c_str());
  return (fileAttr != INVALID_FILE_ATTRIBUTES &&
          (fileAttr & FILE_ATTRIBUTE_DIRECTORY));
}

bool IsKnownFileExtension(const std::vector<std::wstring>& exts, const std::wstring &file) {
  for (const auto& ext : exts) {
    if ((file.size() >= ext.size()) &&
      (_wcsicmp(file.substr(file.size() - ext.size()).c_str(), ext.c_str())))
      return true;
  }
  return false;
}

bool NormalizeDriveName(std::wstring& drive) {
  if ((0 == drive.substr(0, 1).compare(L"\"")) || (0 == drive.substr(0, 1).compare(L"'"))) {
    drive.erase(0, 1);
  }
  if ((0 == drive.substr(drive.size() - 1, 1).compare(L"\"")) || (0 == drive.substr(drive.size() - 1, 1).compare(L"'"))) {
    drive.erase(drive.size() - 1, 1);
  }
  if (0 != drive.substr(drive.size() - 1, 1).compare(L"\\")) {
    drive += L"\\";
  }
  return true;
}

bool NormalizeDirectoryName(std::wstring& dir) {
  if ((0 == dir.substr(0, 1).compare(L"\"")) || (0 == dir.substr(0, 1).compare(L"'"))) {
    dir.erase(0, 1);
  }
  if ((0 == dir.substr(dir.size() - 1, 1).compare(L"\"")) || (0 == dir.substr(dir.size() - 1, 1).compare(L"'"))) {
    dir.erase(dir.size() - 1, 1);
  }
  if (0 != dir.substr(dir.size() - 1, 1).compare(L"\\")) {
    dir += L"\\";
  }
  return true;
}

bool NormalizeFileName(std::wstring& file) {
  if ((0 == file.substr(0, 1).compare(L"\"")) || (0 == file.substr(0, 1).compare(L"'"))) {
    file.erase(0, 1);
  }
  if ((0 == file.substr(file.size() - 1, 1).compare(L"\"")) || (0 == file.substr(file.size() - 1, 1).compare(L"'"))) {
    file.erase(file.size() - 1, 1);
  }
  return true;
}

bool NormalizeFileExtension(std::wstring& ext) {
  if ((0 == ext.substr(0, 1).compare(L"\"")) || (0 == ext.substr(0, 1).compare(L"'"))) {
    ext.erase(0, 1);
  }
  if ((0 == ext.substr(ext.size() - 1, 1).compare(L"\"")) || (0 == ext.substr(ext.size() - 1, 1).compare(L"'"))) {
    ext.erase(ext.size() - 1, 1);
  }
  return true;
}

std::wstring GetHostName() {
  wchar_t buf[1024] = {0};
  DWORD size = _countof(buf);
  std::wstring hostname;

  if (GetComputerNameEx(ComputerNameDnsFullyQualified, buf, &size)) {
    hostname = buf;
  }

  return hostname;
}

std::wstring FormatLocalTime(time_t datetime) {
  wchar_t buf[64] = {0};
  struct tm* tm = NULL;

  tm = localtime(&datetime);
  wcsftime(buf, _countof(buf) - 1, L"%FT%T%z", tm);

  return std::wstring(buf);
}

std::wstring GetScanUtilityDirectory() {
  wchar_t path[MAX_PATH] = {0};
  std::wstring utility_dir;
  std::wstring::size_type pos;
  if (GetModuleFileName(NULL, path, _countof(path))) {
    utility_dir = path;
    pos = utility_dir.find_last_of(L"\\");
    utility_dir = utility_dir.substr(0, pos);
  }
  return utility_dir;
}

std::wstring GetReportDirectory() {
  std::wstring destination_dir;
  std::wstring report_dir;
  if (ExpandEnvironmentVariables(qualys_program_data_location,
                                 destination_dir)) {
    if (!DirectoryExists(destination_dir.c_str())) {
      _wmkdir(destination_dir.c_str());
    }
    report_dir = destination_dir;
  }
  if (report_dir.empty()) {
    report_dir = GetScanUtilityDirectory();
  }
  return report_dir;
}

std::wstring GetSignatureReportFindingsFilename() {
  return GetReportDirectory() + L"\\" + report_sig_output_file;
}

std::wstring GetSignatureReportSummaryFilename() {
  return GetReportDirectory() + L"\\" + report_sig_summary_file;
}

std::wstring GetSignatureStatusFilename() {
  return GetReportDirectory() + L"\\" + report_sig_status_file;
}

std::wstring GetRemediationReportFilename() {
  return GetReportDirectory() + L"\\" + remediation_report_file;
}

std::wstring GetRemediationStatusFilename() {
  return GetReportDirectory() + L"\\" + remediation_status_file;
}

uint32_t LogErrorMessage(bool verbose, const wchar_t* fmt, ...) {
  uint32_t retval = 0;
  va_list ap;
  wchar_t err[1024] = {0};

  if (fmt == NULL) return 0;

  if (verbose) {
    va_start(ap, fmt);
    vfwprintf(stdout, fmt, ap);
    fwprintf(stdout, L"\n");
    va_end(ap);
  }

  va_start(ap, fmt);
  retval = vswprintf(err, _countof(err), fmt, ap);
  va_end(ap);
  error_array.push_back(err);

  return retval;
}

bool OpenStatusFile(const std::wstring& filename) {
  errno_t err = _wfopen_s(&status_file, filename.c_str(), L"w+, ccs=UTF-8");
  return (EINVAL != err);
}

uint32_t LogStatusMessage(const wchar_t* fmt, ...) {
  uint32_t retval = 0;
  va_list ap;

  if (fmt == NULL) return 0;

  va_start(ap, fmt);
  vfwprintf(stdout, fmt, ap);
  fwprintf(stdout, L"\n");
  va_end(ap);

  if (status_file) {
    va_start(ap, fmt);
    retval = vfwprintf(status_file, fmt, ap);
    fwprintf(status_file, L"\n");
    va_end(ap);
    fflush(status_file);
  }

  return retval;
}

bool CloseStatusFile() {
  if (status_file) {
    fclose(status_file);
  }
  return true;
}

bool ParseVersion(std::string version, int& major, int& minor, int& build) {
  return (0 != sscanf_s(version.c_str(), "%d.%d.%d", &major, &minor, &build));
}

bool IsCVE20214104Mitigated(std::string log4jVendor, std::string version) {
  int major = 0, minor = 0, build = 0;
  if (log4jVendor != "log4j") return true;
  if (ParseVersion(version, major, minor, build)) {
    if ((major >= 2) || (major < 1)) return true;
    if ((major == 1) && (minor <= 1)) return true;
    if ((major == 1) && (minor == 2) && (build >= 17)) return true;
    if ((major == 1) && (minor >= 3)) return true;
  }
  return false;
}

bool IsCVE202144228Mitigated(std::string log4jVendor, bool foundJNDILookupClass,
                             std::string version) {
  int major = 0, minor = 0, build = 0;
  if (!foundJNDILookupClass) return true;
  if (log4jVendor !="log4j-core") return true;  // Impacted JAR
  if (ParseVersion(version, major, minor, build)) {
    if (major < 2) return true;                                      // N/A
    if ((major == 2) && (minor == 3) && (build >= 1)) return true;   // Java 6
    if ((major == 2) && (minor == 12) && (build >= 2)) return true;  // Java 7
    if ((major == 2) && (minor >= 15)) return true;                  // Java 8+
  }
  return false;
}

bool IsCVE202144832Mitigated(std::string log4jVendor, std::string version) {
  int major = 0, minor = 0, build = 0;
  if (log4jVendor != "log4j-core") return true;  // Impacted JAR
  if (ParseVersion(version, major, minor, build)) {
    if (major < 2) return true;                                      // N/A
    if ((major == 2) && (minor == 3) && (build >= 2)) return true;   // Java 6
    if ((major == 2) && (minor == 12) && (build >= 4)) return true;  // Java 7
    if ((major == 2) && (minor == 17) && (build >= 1)) return true;  // Java 8+
    if ((major == 2) && (minor >= 18)) return true;                  // Java 8+
  }
  return false;
}

bool IsCVE202145046Mitigated(std::string log4jVendor, bool foundJNDILookupClass,
                             std::string version) {
  int major = 0, minor = 0, build = 0;
  if (!foundJNDILookupClass) return true;
  if (log4jVendor != "log4j-core") return true;  // Impacted JAR
  if (ParseVersion(version, major, minor, build)) {
    if (major < 2) return true;                                      // N/A
    if ((major == 2) && (minor == 3) && (build >= 1)) return true;   // Java 6
    if ((major == 2) && (minor == 12) && (build >= 2)) return true;  // Java 7
    if ((major == 2) && (minor >= 16)) return true;                  // Java 8+
  }
  return false;
}

bool IsCVE202145105Mitigated(std::string log4jVendor, std::string version) {
  int major = 0, minor = 0, build = 0;
  if (log4jVendor != "log4j-core") return true;  // Impacted JAR
  if (ParseVersion(version, major, minor, build)) {
    if (major < 2) return true;                                      // N/A
    if ((major == 2) && (minor == 3) && (build >= 1)) return true;   // Java 6
    if ((major == 2) && (minor == 12) && (build >= 2)) return true;  // Java 7
    if ((major == 2) && (minor >= 17)) return true;                  // Java 8+
  }
  return false;
}

int DumpGenericException(const wchar_t* szExceptionDescription,
                         DWORD dwExceptionCode, PVOID pExceptionAddress) {
  LogStatusMessage(L"Unhandled Exception Detected - Reason: %s (0x%x) at address 0x%p\n\n",
    szExceptionDescription, 
    dwExceptionCode, 
    pExceptionAddress);

  return 0;
}

int DumpExceptionRecord(PEXCEPTION_POINTERS pExPtrs) {
  PVOID pExceptionAddress = pExPtrs->ExceptionRecord->ExceptionAddress;
  DWORD dwExceptionCode = pExPtrs->ExceptionRecord->ExceptionCode;

  switch (dwExceptionCode) {
    case 0xE06D7363:
      DumpGenericException(L"Out Of Memory (C++ Exception)", dwExceptionCode, pExceptionAddress);
      break;
    case EXCEPTION_ACCESS_VIOLATION:
      wchar_t szStatus[256];
      wchar_t szSubStatus[256];
      wcscpy_s(szStatus, L"Access Violation");
      wcscpy_s(szSubStatus, L"");
      if (pExPtrs->ExceptionRecord->NumberParameters == 2) {
        switch (pExPtrs->ExceptionRecord->ExceptionInformation[0]) {
          case 0:  // read attempt
            swprintf_s(szSubStatus, L"read attempt to address 0x%p",
                       (void*)pExPtrs->ExceptionRecord->ExceptionInformation[1]);
            break;
          case 1:  // write attempt
            swprintf_s(szSubStatus, L"write attempt to address 0x%p",
                       (void*)pExPtrs->ExceptionRecord->ExceptionInformation[1]);
            break;
        }
      }
      LogStatusMessage(
          L"Unhandled Exception Detected - Reason: %s(0x%x) at address 0x%p %s\n\n",
          szStatus, dwExceptionCode, pExceptionAddress, szSubStatus);
      break;
    case EXCEPTION_DATATYPE_MISALIGNMENT:
      DumpGenericException(L"Data Type Misalignment", dwExceptionCode,
                           pExceptionAddress);
      break;
    case EXCEPTION_BREAKPOINT:
      DumpGenericException(L"Breakpoint Encountered", dwExceptionCode,
                           pExceptionAddress);
      break;
    case EXCEPTION_SINGLE_STEP:
      DumpGenericException(L"Single Instruction Executed", dwExceptionCode,
                           pExceptionAddress);
      break;
    case EXCEPTION_ARRAY_BOUNDS_EXCEEDED:
      DumpGenericException(L"Array Bounds Exceeded", dwExceptionCode,
                           pExceptionAddress);
      break;
    case EXCEPTION_FLT_DENORMAL_OPERAND:
      DumpGenericException(L"Float Denormal Operand", dwExceptionCode,
                           pExceptionAddress);
      break;
    case EXCEPTION_FLT_DIVIDE_BY_ZERO:
      DumpGenericException(L"Divide by Zero", dwExceptionCode,
                           pExceptionAddress);
      break;
    case EXCEPTION_FLT_INEXACT_RESULT:
      DumpGenericException(L"Float Inexact Result", dwExceptionCode,
                           pExceptionAddress);
      break;
    case EXCEPTION_FLT_INVALID_OPERATION:
      DumpGenericException(L"Float Invalid Operation", dwExceptionCode,
                           pExceptionAddress);
      break;
    case EXCEPTION_FLT_OVERFLOW:
      DumpGenericException(L"Float Overflow", dwExceptionCode,
                           pExceptionAddress);
      break;
    case EXCEPTION_FLT_STACK_CHECK:
      DumpGenericException(L"Float Stack Check", dwExceptionCode,
                           pExceptionAddress);
      break;
    case EXCEPTION_FLT_UNDERFLOW:
      DumpGenericException(L"Float Underflow", dwExceptionCode,
                           pExceptionAddress);
      break;
    case EXCEPTION_INT_DIVIDE_BY_ZERO:
      DumpGenericException(L"Integer Divide by Zero", dwExceptionCode,
                           pExceptionAddress);
      break;
    case EXCEPTION_INT_OVERFLOW:
      DumpGenericException(L"Integer Overflow", dwExceptionCode,
                           pExceptionAddress);
      break;
    case EXCEPTION_PRIV_INSTRUCTION:
      DumpGenericException(L"Privileged Instruction", dwExceptionCode,
                           pExceptionAddress);
      break;
    case EXCEPTION_IN_PAGE_ERROR:
      DumpGenericException(L"In Page Error", dwExceptionCode, pExceptionAddress);
      break;
    case EXCEPTION_ILLEGAL_INSTRUCTION:
      DumpGenericException(L"Illegal Instruction", dwExceptionCode,
                           pExceptionAddress);
      break;
    case EXCEPTION_NONCONTINUABLE_EXCEPTION:
      DumpGenericException(L"Noncontinuable Exception", dwExceptionCode,
                           pExceptionAddress);
      break;
    case EXCEPTION_STACK_OVERFLOW:
      DumpGenericException(L"Stack Overflow", dwExceptionCode,
                           pExceptionAddress);
      break;
    case EXCEPTION_INVALID_DISPOSITION:
      DumpGenericException(L"Invalid Disposition", dwExceptionCode,
                           pExceptionAddress);
      break;
    case EXCEPTION_GUARD_PAGE:
      DumpGenericException(L"Guard Page Violation", dwExceptionCode,
                           pExceptionAddress);
      break;
    case EXCEPTION_INVALID_HANDLE:
      DumpGenericException(L"Invalid Handle", dwExceptionCode,
                           pExceptionAddress);
      break;
    case CONTROL_C_EXIT:
      DumpGenericException(L"Ctrl+C Exit", dwExceptionCode, pExceptionAddress);
      break;
    default:
      DumpGenericException(L"Unknown exception", dwExceptionCode,
                           pExceptionAddress);
      break;
  }

  return 0;
}

LONG CALLBACK CatchUnhandledExceptionFilter(PEXCEPTION_POINTERS pExPtrs) {
  WCHAR szMiniDumpFileName[MAX_PATH];
  HANDLE hDumpFile = NULL;
  SYSTEMTIME sysTime;
  SECURITY_ATTRIBUTES saMiniDumpSecurity;

  LogStatusMessage(L"Run status : Failed\n");

  // Attempt to dump an unhandled exception banner just in case things are
  // so bad that a minidump cannot be created.
  DumpExceptionRecord(pExPtrs);

  // Create a directory to dump the minidump files into
  SecureZeroMemory(&saMiniDumpSecurity, sizeof(saMiniDumpSecurity));
  saMiniDumpSecurity.nLength = sizeof(saMiniDumpSecurity);
  saMiniDumpSecurity.bInheritHandle = FALSE;

  // Construct a valid minidump filename that will be unique.
  // Use the '.mdmp' extension so it'll be recognize by the Windows debugging
  // tools.
  GetLocalTime(&sysTime);
  swprintf_s(szMiniDumpFileName,
             L"%s\\%0.2d%0.2d%0.4d%d%0.2d%0.2d%0.4d.mdmp",
             GetScanUtilityDirectory().c_str(),
             sysTime.wMonth,
             sysTime.wDay,
             sysTime.wYear,
             sysTime.wHour,
             sysTime.wMinute,
             sysTime.wSecond,
             sysTime.wMilliseconds);

  LogStatusMessage(L"Creating minidump file %s with crash details.\n",
                   szMiniDumpFileName);

  // Create the file to dump the minidump data into...
  //
  hDumpFile = CreateFile(szMiniDumpFileName, GENERIC_WRITE, NULL, NULL,
                         CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

  if (hDumpFile != INVALID_HANDLE_VALUE) {
    MINIDUMP_EXCEPTION_INFORMATION eiMinidumpInfo;
    SecureZeroMemory(&eiMinidumpInfo, sizeof(eiMinidumpInfo));
    eiMinidumpInfo.ThreadId = GetCurrentThreadId();
    eiMinidumpInfo.ExceptionPointers = pExPtrs;
    eiMinidumpInfo.ClientPointers = FALSE;

    //
    // Write the Mini Dump to disk
    //
    if (!MiniDumpWriteDump(
            GetCurrentProcess(), GetCurrentProcessId(), hDumpFile,
            (MINIDUMP_TYPE)(MiniDumpNormal |
                            MiniDumpWithPrivateReadWriteMemory |
                            MiniDumpWithDataSegs | MiniDumpWithHandleData |
                            MiniDumpWithFullMemoryInfo |
                            MiniDumpWithThreadInfo |
                            MiniDumpWithUnloadedModules |
                            MiniDumpWithIndirectlyReferencedMemory),
            &eiMinidumpInfo, NULL, NULL)) {
      // Either the state of the process is beyond our ability to be able
      // to scape together a usable dump file or we are on XP/2k3 and
      // not all of the dump flags are supported.  Retry using dump flags
      // that are supported by XP.
      //
      if (!MiniDumpWriteDump(
              GetCurrentProcess(), GetCurrentProcessId(), hDumpFile,
              (MINIDUMP_TYPE)(MiniDumpNormal |
                              MiniDumpWithPrivateReadWriteMemory |
                              MiniDumpWithDataSegs | MiniDumpWithHandleData),
              &eiMinidumpInfo, NULL, NULL)) {
        // Well out XP/2k3 compatible list of parameters didn't work, it
        // doesn't look like we will be able to get anything useful.
        //
        // Close things down and delete the file if it exists.
        //
        SAFE_CLOSE_HANDLE(hDumpFile);
        DeleteFile(szMiniDumpFileName);

        LogStatusMessage(L"Failed to create minidump file %s.\n", szMiniDumpFileName);
      }
    }

    SAFE_CLOSE_HANDLE(hDumpFile);
  }

  TerminateProcess(GetCurrentProcess(), pExPtrs->ExceptionRecord->ExceptionCode);

  return 0;
}