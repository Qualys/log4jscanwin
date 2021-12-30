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

constexpr wchar_t* qualys_program_data_location = L"%ProgramData%\\Qualys";
constexpr wchar_t* report_sig_output_file = L"log4j_findings.out";
constexpr wchar_t* report_sig_status_file = L"status.txt";

constexpr wchar_t* remediation_report_file = L"log4j_remediate.out";
constexpr wchar_t* remediation_status_file = L"remediation_status.out";

std::wstring A2W(const std::string& str);
std::string W2A(const std::wstring& str);
void SplitWideString(std::wstring str, const std::wstring& token, std::vector<std::wstring>& result);
bool SanitizeContents(std::string& str);
bool StripWhitespace(std::string& str);
bool GetDictionaryValue(std::string& dict, std::string name, std::string defaultValue, std::string& value);
bool ExpandEnvironmentVariables(const wchar_t* source, std::wstring& destination);
bool DirectoryExists(const wchar_t* dirPath);
std::wstring GetScanUtilityDirectory();
std::wstring GetReportDirectory();
std::wstring GetSignatureReportFilename();
std::wstring GetSignatureStatusFilename();
std::wstring GetRemediationReportFilename();
std::wstring GetRemediationStatusFilename();
bool OpenStatusFile(const std::wstring & filename);
int LogStatusMessage(const wchar_t* fmt, ...);
bool CloseStatusFile();

bool ParseVersion(std::string version, int& major, int& minor, int& build);
bool IsCVE20214104Mitigated(std::string log4jVendor, std::string version);
bool IsCVE202144228Mitigated(std::string log4jVendor, bool foundJNDILookupClass, std::string version);
bool IsCVE202144832Mitigated(std::string log4jVendor, std::string version);
bool IsCVE202145046Mitigated(std::string log4jVendor, bool foundJNDILookupClass, std::string version);
bool IsCVE202145105Mitigated(std::string log4jVendor, std::string version);

LONG CALLBACK CatchUnhandledExceptionFilter(PEXCEPTION_POINTERS pExPtrs);

extern std::vector<std::wstring> error_array;
