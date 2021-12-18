#pragma once


#define SAFE_CLOSE_HANDLE(x)                  \
  do {                                        \
    if ((x) && INVALID_HANDLE_VALUE != (x)) { \
      ::CloseHandle(x);                       \
      (x) = INVALID_HANDLE_VALUE;             \
    }                                         \
  } while (FALSE)


std::wstring A2W(const std::string& str);
std::string W2A(const std::wstring& str);
bool SanitizeContents(std::string& str);
bool StripWhitespace(std::string& str);
bool GetDictionaryValue(std::string& dict, std::string name, std::string defaultValue, std::string& value);
bool ExpandEnvironmentVariables(const wchar_t* source, std::wstring& destination);
bool DirectoryExists(const wchar_t* dirPath);
std::wstring GetScanUtilityDirectory();
std::wstring GetReportDirectory();
std::wstring GetSignatureReportFilename();
std::wstring GetSignatureStatusFilename();
bool OpenSignatureStatusFile();
int LogStatusMessage(const wchar_t* fmt, ...);
bool CloseSignatureStatusFile();

LONG CALLBACK CatchUnhandledExceptionFilter(PEXCEPTION_POINTERS pExPtrs);

extern std::vector<std::wstring> error_array;

