#pragma once

class CReportSummary {
 public:
  uint64_t scannedFiles;
  uint64_t scannedDirectories;
  uint64_t scannedZIPs;
  uint64_t scannedJARs;
  uint64_t scannedWARs;
  uint64_t scannedEARs;
  uint64_t foundVunerabilities;
  uint64_t scanStart;
  uint64_t scanEnd;

  CReportSummary() {
    scannedFiles = 0;
    scannedDirectories = 0;
    scannedZIPs = 0;
    scannedJARs = 0;
    scannedWARs = 0;
    scannedEARs = 0;
    foundVunerabilities = 0;
    scanStart = 0;
    scanEnd = 0;
  }
};

class CReportVunerabilities {
 public:
  std::wstring file;
  std::wstring manifestVersion;
  std::wstring manifestVendor;
  bool detectedLog4j;
  bool detectedLog4j1x;
  bool detectedLog4j2x;
  bool detectedJNDILookupClass;
  bool detectedLog4jManifest;
  std::wstring log4jVersion;
  std::wstring log4jVendor;
  bool cve20214104Mitigated;
  bool cve202144228Mitigated;
  bool cve202145046Mitigated;
  bool cve202145105Mitigated;
  std::wstring cveStatus;

  CReportVunerabilities(std::wstring file, std::wstring manifestVersion,
                        std::wstring manifestVendor, bool detectedLog4j,
                        bool detectedLog4j1x, bool detectedLog4j2x,
                        bool detectedJNDILookupClass,
                        bool detectedLog4jManifest, std::wstring log4jVersion,
                        std::wstring log4jVendor, bool cve20214104Mitigated,
                        bool cve202144228Mitigated, bool cve202145046Mitigated,
                        bool cve202145105Mitigated, std::wstring cveStatus) {
    this->file = file;
    this->manifestVersion = manifestVersion;
    this->manifestVendor = manifestVendor;
    this->detectedLog4j = detectedLog4j;
    this->detectedLog4j1x = detectedLog4j1x;
    this->detectedLog4j2x = detectedLog4j2x;
    this->detectedJNDILookupClass = detectedJNDILookupClass;
    this->detectedLog4jManifest = detectedLog4jManifest;
    this->log4jVersion = log4jVersion;
    this->log4jVendor = log4jVendor;
    this->cve20214104Mitigated = cve20214104Mitigated;
    this->cve202144228Mitigated = cve202144228Mitigated;
    this->cve202145046Mitigated = cve202145046Mitigated;
    this->cve202145105Mitigated = cve202145105Mitigated;
    this->cveStatus = cveStatus;
  }
};


extern CReportSummary repSummary;
extern std::vector<CReportVunerabilities> repVulns;


int32_t GenerateJSONReport();
int32_t GenerateSignatureReport();

