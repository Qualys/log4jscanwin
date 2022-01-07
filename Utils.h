#pragma once


#define SAFE_CLOSE_HANDLE(x)                  \
  do {                                        \
    if ((x) && INVALID_HANDLE_VALUE != (x)) { \
      ::CloseHandle(x);                       \
      (x) = INVALID_HANDLE_VALUE;             \
    }                                         \
  } while (FALSE)


typedef std::stack<std::pair<std::wstring, std::wstring>> PairStack;
typedef std::pair<std::wstring, std::wstring> StringPair;


bool IsFileTarball(std::wstring file);
bool IsFileCompressedGZIPTarball(std::wstring file);
bool IsFileZIPArchive(std::wstring file);

std::wstring A2W(const std::string& str);
std::string W2A(const std::wstring& str);

std::wstring FormatLocalTime(time_t datetime);
bool GetDictionaryValue(std::string& dict, std::string name, std::string defaultValue, std::string& value);
bool SanitizeContents(std::string& str);
void SplitWideString(std::wstring str, const std::wstring& token, std::vector<std::wstring>& result);
bool StripWhitespace(std::string& str);

bool ExpandEnvironmentVariables(const wchar_t* source, std::wstring& destination);
bool DirectoryExists(const wchar_t* dirPath);

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
