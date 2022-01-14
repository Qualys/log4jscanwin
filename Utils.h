#pragma once


#define SAFE_CLOSE_HANDLE(x)                  \
  do {                                        \
    if ((x) && INVALID_HANDLE_VALUE != (x)) { \
      ::CloseHandle(x);                       \
      (x) = INVALID_HANDLE_VALUE;             \
    }                                         \
  } while (FALSE)


#define ARGX3(s1, s2, s3) \
  (!_wcsicmp(argv[i], s1) || !_wcsicmp(argv[i], s2) || !_wcsicmp(argv[i], s3))
#define ARG(S) ARGX3(L"-" #S, L"--" #S, L"/" #S)
#define ARGPARAMCOUNT(X) ((i + X) <= (argc - 1))

using PairStack = std::stack<std::pair<std::wstring, std::wstring>>;
using StringPair = std::pair<std::wstring, std::wstring>;

std::wstring A2W(const std::string& str);
std::string W2A(const std::wstring& str);
std::wstring GetTempFilePath(const std::wstring & prefix = L"ljr");
bool StartsWithCaseInsensitive(const std::wstring & text, const std::wstring & prefix);

std::wstring FormatLocalTime(time_t datetime);
bool GetDictionaryValue(std::string& dict, std::string name, std::string defaultValue, std::string& value);
bool SanitizeContents(std::string& str);
void SplitWideString(std::wstring str, const std::wstring& token, std::vector<std::wstring>& result);
bool StripWhitespace(std::string& str);

bool ExpandEnvironmentVariables(const wchar_t* source, std::wstring& destination);
bool DirectoryExists(std::wstring directory);
bool IsKnownFileExtension(const std::vector<std::wstring>& exts, const std::wstring &file);
bool NormalizeDriveName(std::wstring& drive);
bool NormalizeDirectoryName(std::wstring& dir);
bool NormalizeFileName(std::wstring& file);
bool NormalizeFileExtension(std::wstring& ext);

std::wstring GetHostName();
std::wstring GetScanUtilityDirectory();
std::wstring GetReportDirectory();
std::wstring GetSignatureReportFindingsFilename();
std::wstring GetSignatureReportSummaryFilename();
std::wstring GetSignatureStatusFilename();
std::wstring GetRemediationReportFilename();
std::wstring GetRemediationStatusFilename();

bool OpenStatusFile(const std::wstring& filename);
bool CloseStatusFile();
uint32_t LogStatusMessage(const wchar_t* fmt, ...);
uint32_t LogErrorMessage(bool verbose, const wchar_t* fmt, ...);

bool ParseVersion(std::string version, int& major, int& minor, int& build);
bool IsCVE20214104Mitigated(std::string log4jVendor, std::string version);
bool IsCVE202144228Mitigated(std::string log4jVendor, bool foundJNDILookupClass, std::string version);
bool IsCVE202144832Mitigated(std::string log4jVendor, std::string version);
bool IsCVE202145046Mitigated(std::string log4jVendor, bool foundJNDILookupClass, std::string version);
bool IsCVE202145105Mitigated(std::string log4jVendor, std::string version);

LONG CALLBACK CatchUnhandledExceptionFilter(PEXCEPTION_POINTERS pExPtrs);

extern std::vector<std::wstring> error_array;
