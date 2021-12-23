
#include "stdafx.h"
#include "Reports.h"
#include "Remediate.h"
#include "Utils.h"

#include <fstream>
#include <sstream>
#include <codecvt>
#include <regex>

const std::wregex line1_regex(L"Source: Manifest Vendor: ([^,]*), Manifest Version: ([^,]*), JNDI Class: ([^,]*), Log4j Vendor: ([^,]*), Log4j Version: ([^,]*)");
const std::wregex line2_regex(L"Path=(.*)");

bool ReadSignatureReport(const std::wstring& report, std::vector<CReportVunerabilities>& result) {
  bool success{};
  DWORD file_size{};
  PBYTE buffer{};
  FILE* scan_file{};
  wchar_t error[1024]{};
  std::vector<std::wstring> lines;  

  std::wifstream wif(report);
  wif.imbue(std::locale(std::locale::empty(), new std::codecvt_utf8<wchar_t>));
  std::wstringstream wss;
  wss << wif.rdbuf();
  SplitWideString(wss.str(), L"\n", lines);

  for (uint32_t index = 0; index < lines.size(); index += SIGNATURE_ITEM_LENGTH) {
    std::wsmatch wsm1, wsm2;
    if (std::regex_match(lines[index].cbegin(), lines[index].cend(), wsm1, line1_regex)
      && std::regex_match(lines[index + 1].cbegin(), lines[index + 1].cend(), wsm2, line2_regex)) {

      std::wstring vendor = wsm1[1].str();
      std::wstring manifest_version = wsm1[2].str();
      bool jndi_class_found = (wsm1[3].str() == L"Found" ? true : false);
      std::wstring log4j_vendor = wsm1[4].str();
      std::wstring log4j_version = wsm1[5].str();
      std::wstring file = wsm2[1].str();
      
      result.emplace_back(file, manifest_version, vendor, false, false, false, jndi_class_found, false, log4j_version, log4j_vendor, false, false, false, false, L"");
    }
    else {
      swprintf_s(error, L"Failed to parse file %s", report.c_str());
      error_array.push_back(error);
      goto END;
    }
  }

  success = true;

END:

  if (wif.is_open()) {
    wif.close();
  }

  return success;
}

bool RemediateFile(const std::wstring& file) {
  bool success{};

  // Add fix logic here

  return success;
}

bool RemediateFromSignatureReport() {
  bool success{};  
  wchar_t error[1024]{};
  std::wstring signature_file;
  std::vector<CReportVunerabilities> vulnerabilities;

  if (!ExpandEnvironmentVariables(qualys_program_data_location, signature_file)) {
    swprintf_s(error, L"Failed to expand path %s", qualys_program_data_location);
    error_array.push_back(error);
    goto END;
  }
    
  signature_file.append(L"\\").append(report_sig_output_file);

  if (!ReadSignatureReport(signature_file, vulnerabilities)) {
    swprintf_s(error, L"Failed to read signature file %s", signature_file.c_str());
    error_array.push_back(error);
    goto END;
  }  

  // Add fix logic here

  success = true;

END:

  return success;
}

bool DeleteVulnerabilityFromReport(const CReportVunerabilities& vulnerability) {
  bool success{};
  wchar_t error[1024]{};
  std::wstring signature_file;
  std::vector<CReportVunerabilities> report;

  if (!ExpandEnvironmentVariables(qualys_program_data_location, signature_file)) {
    swprintf_s(error, L"Failed to expand path %s", qualys_program_data_location);
    error_array.push_back(error);
    goto END;
  }

  signature_file.append(L"\\").append(report_sig_output_file);

  if (!ReadSignatureReport(signature_file, report)) {
    swprintf_s(error, L"Failed to read signature file %s", signature_file.c_str());
    error_array.push_back(error);
    goto END;
  }

  success = true;
END:

  return success;
}
