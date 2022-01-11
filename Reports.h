#pragma once

class CReportSummary {
public:
  uint64_t scannedFiles;
  uint64_t scannedDirectories;
  uint64_t scannedCompressed;
  uint64_t scannedJARs;
  uint64_t scannedWARs;
  uint64_t scannedEARs;
  uint64_t scannedTARs;
  uint64_t foundVunerabilities;
  uint64_t scanStart;
  uint64_t scanEnd;
  uint64_t scanErrorCount;
  std::wstring scanStatus;
  std::vector<std::wstring> excludedDrives;
  std::vector<std::wstring> excludedDirectories;
  std::vector<std::wstring> excludedFiles;
  std::vector<std::wstring> knownTarExtensions;
  std::vector<std::wstring> knownGZipTarExtensions;
  std::vector<std::wstring> knownBZipTarExtensions;
  std::vector<std::wstring> knownZipExtensions;

  CReportSummary() {
    scannedFiles = 0;
    scannedDirectories = 0;
    scannedCompressed = 0;
    scannedJARs = 0;
    scannedWARs = 0;
    scannedEARs = 0;
    scannedTARs = 0;
    foundVunerabilities = 0;
    scanStart = 0;
    scanEnd = 0;
    scanErrorCount = 0;
    scanStatus.clear();
    excludedDrives.clear();
    excludedDirectories.clear();
    excludedFiles.clear();
    knownTarExtensions.clear();
    knownGZipTarExtensions.clear();
    knownBZipTarExtensions.clear();
    knownZipExtensions.clear();
  }
};

struct CRemediationSummary {  
  uint64_t scanStart;
  uint64_t scanEnd;

  CRemediationSummary() {    
    scanStart = 0;
    scanEnd = 0;
  }
};

class CReportVulnerabilities {
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
  bool cve202144832Mitigated;
  bool cve202145046Mitigated;
  bool cve202145105Mitigated;
  std::wstring cveStatus;

  CReportVulnerabilities(std::wstring file, std::wstring manifestVersion,
                        std::wstring manifestVendor, bool detectedLog4j,
                        bool detectedLog4j1x, bool detectedLog4j2x,
                        bool detectedJNDILookupClass,
                        bool detectedLog4jManifest, std::wstring log4jVersion,
                        std::wstring log4jVendor, bool cve20214104Mitigated,
                        bool cve202144228Mitigated, bool cve202144832Mitigated,
                        bool cve202145046Mitigated, bool cve202145105Mitigated,
                        std::wstring cveStatus) {
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
    this->cve202144832Mitigated = cve202144832Mitigated;
    this->cve202145046Mitigated = cve202145046Mitigated;
    this->cve202145105Mitigated = cve202145105Mitigated;
    this->cveStatus = cveStatus;
  }
};


extern CReportSummary repSummary;
extern CRemediationSummary remSummary;
extern std::vector<CReportVulnerabilities> repVulns;

int32_t ReportProcessJARFile();
int32_t ReportProcessWARFile();
int32_t ReportProcessEARFile();
int32_t ReportProcessTARFile();
int32_t ReportProcessCompressedFile();
int32_t ReportProcessDirectory();
int32_t ReportProcessFile();

int32_t GenerateJSONReport(bool pretty);
int32_t GenerateSignatureReport();

int32_t AddToRemediationReport(const CReportVulnerabilities& vuln);
int32_t GenerateRemediationJSONReport(bool pretty);
