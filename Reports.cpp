
#include "stdafx.h"
#include "Utils.h"
#include "Reports.h"
#include "Version.info"

#include "rapidjson/document.h"
#include "rapidjson/prettywriter.h"
#include "rapidjson/stringbuffer.h"
#include "rapidjson/writer.h"


using DocumentW = rapidjson::GenericDocument<rapidjson::UTF16<>>;
using ValueW = rapidjson::GenericValue<rapidjson::UTF16<>>;
using WriterW = rapidjson::Writer<rapidjson::StringBuffer, rapidjson::UTF16<>, rapidjson::UTF8<>>;
using PrettyWriterW = rapidjson::PrettyWriter<rapidjson::StringBuffer, rapidjson::UTF16<>, rapidjson::UTF8<>>;


CReportSummary repSummary;
CRemediationSummary remSummary;
std::vector<CReportVulnerabilities> repVulns;


int32_t ReportProcessJARFile() {
  repSummary.scannedJARs++;
  return ERROR_SUCCESS;
}

int32_t ReportProcessWARFile() {
  repSummary.scannedWARs++;
  return ERROR_SUCCESS;
}

int32_t ReportProcessEARFile() {
  repSummary.scannedEARs++;
  return ERROR_SUCCESS;
}

int32_t ReportProcessDirectory(std::wstring Directory) {
  repSummary.scannedDirectories++;
  return ERROR_SUCCESS;
}

int32_t ReportProcessFile(std::wstring file) {
  int32_t rv = ERROR_SUCCESS;
  wchar_t drive[_MAX_DRIVE];
  wchar_t dir[_MAX_DIR];
  wchar_t fname[_MAX_FNAME];
  wchar_t ext[_MAX_EXT];

  repSummary.scannedFiles++;
  if (IsFileZIPArchive(file)) {
    repSummary.scannedCompressed++;
  }

  if (0 == _wsplitpath_s(file.c_str(), drive, dir, fname, ext)) {
    if (0 == _wcsicmp(ext, L".tar")) {
      repSummary.scannedTARs++;
    }
    if (0 == _wcsicmp(ext, L".tgz")) {
      repSummary.scannedCompressed++;
    }
    if (0 == _wcsicmp(ext, L".gz")) {
      repSummary.scannedCompressed++;
    }
  }
  return rv;
}

int32_t GenerateReportSummary(DocumentW& doc) {
  int32_t rv = ERROR_SUCCESS;

  ValueW vScanEngine(rapidjson::kStringType);
  ValueW vScanHostname(rapidjson::kStringType);
  ValueW vScanDate(rapidjson::kStringType);
  ValueW vScanDuration(rapidjson::kNumberType);
  ValueW vScanErrorCount(rapidjson::kNumberType);
  ValueW vScanStatus(rapidjson::kStringType);
  ValueW vScannedFiles(rapidjson::kNumberType);
  ValueW vScannedDirectories(rapidjson::kNumberType);
  ValueW vScannedJARs(rapidjson::kNumberType);
  ValueW vScannedWARs(rapidjson::kNumberType);
  ValueW vScannedEARs(rapidjson::kNumberType);
  ValueW vScannedPARs(rapidjson::kNumberType);
  ValueW vScannedTARs(rapidjson::kNumberType);
  ValueW vScannedCompressed(rapidjson::kNumberType);
  ValueW vVulnerabilitiesFound(rapidjson::kNumberType);
  ValueW oSummary(rapidjson::kObjectType);

  vScanEngine.SetString(A2W(SCANNER_VERSION_STRING).c_str(), doc.GetAllocator());
  vScanHostname.SetString(GetHostName().c_str(), doc.GetAllocator());
  vScanDate.SetString(FormatLocalTime(repSummary.scanStart).c_str(), doc.GetAllocator());
  vScanDuration.SetInt64(repSummary.scanEnd - repSummary.scanStart);
  vScanErrorCount.SetInt64(repSummary.scanErrorCount);
  vScanStatus.SetString(repSummary.scanStatus.c_str(), doc.GetAllocator());
  vScannedFiles.SetInt64(repSummary.scannedFiles);
  vScannedDirectories.SetInt64(repSummary.scannedDirectories);
  vScannedJARs.SetInt64(repSummary.scannedJARs);
  vScannedWARs.SetInt64(repSummary.scannedWARs);
  vScannedEARs.SetInt64(repSummary.scannedEARs);
  vScannedTARs.SetInt64(repSummary.scannedTARs);
  vScannedCompressed.SetInt64(repSummary.scannedCompressed);
  vVulnerabilitiesFound.SetInt64(repSummary.foundVunerabilities);

  oSummary.AddMember(L"scanEngine", vScanEngine, doc.GetAllocator());
  oSummary.AddMember(L"scanHostname", vScanHostname, doc.GetAllocator());
  oSummary.AddMember(L"scanDate", vScanDate, doc.GetAllocator());
  oSummary.AddMember(L"scanDurationSeconds", vScanDuration, doc.GetAllocator());
  oSummary.AddMember(L"scanErrorCount", vScanErrorCount, doc.GetAllocator());
  oSummary.AddMember(L"scanStatus", vScanStatus, doc.GetAllocator());
  oSummary.AddMember(L"scannedFiles", vScannedFiles, doc.GetAllocator());
  oSummary.AddMember(L"scannedDirectories", vScannedDirectories, doc.GetAllocator());
  oSummary.AddMember(L"scannedJARs", vScannedJARs, doc.GetAllocator());
  oSummary.AddMember(L"scannedWARs", vScannedWARs, doc.GetAllocator());
  oSummary.AddMember(L"scannedEARs", vScannedEARs, doc.GetAllocator());
  oSummary.AddMember(L"scannedTARs", vScannedTARs, doc.GetAllocator());
  oSummary.AddMember(L"scannedCompressed", vScannedCompressed, doc.GetAllocator());
  oSummary.AddMember(L"vulnerabilitiesFound", vVulnerabilitiesFound, doc.GetAllocator());

  doc.AddMember(L"scanSummary", oSummary, doc.GetAllocator());

  return rv;
}

int32_t GenerateReportDetail(DocumentW& doc) {
  int32_t rv = ERROR_SUCCESS;
  ValueW oDetails(rapidjson::kArrayType);

  for (size_t i = 0; i < repVulns.size(); i++) {
    CReportVulnerabilities vuln = repVulns[i];

    ValueW vFile(rapidjson::kStringType);
    ValueW vManifestVendor(rapidjson::kStringType);
    ValueW vManifestVersion(rapidjson::kStringType);
    ValueW vDetectedLog4j(rapidjson::kTrueType);
    ValueW vDetectedLog4j1x(rapidjson::kTrueType);
    ValueW vDetectedLog4j2x(rapidjson::kTrueType);
    ValueW vDetectedJNDILookupClass(rapidjson::kTrueType);
    ValueW vDetectedLog4jManifest(rapidjson::kTrueType);
    ValueW vLog4jVendor(rapidjson::kStringType);
    ValueW vLog4jVersion(rapidjson::kStringType);
    ValueW vCVE20214104Mitigated(rapidjson::kTrueType);
    ValueW vCVE202144228Mitigated(rapidjson::kTrueType);
    ValueW vCVE202144832Mitigated(rapidjson::kTrueType);
    ValueW vCVE202145046Mitigated(rapidjson::kTrueType);
    ValueW vCVE202145105Mitigated(rapidjson::kTrueType);
    ValueW vCVEStatus(rapidjson::kStringType);
    ValueW oDetail(rapidjson::kObjectType);

    vFile.SetString(vuln.file.c_str(), doc.GetAllocator());
    vManifestVendor.SetString(vuln.manifestVendor.c_str(), doc.GetAllocator());
    vManifestVersion.SetString(vuln.manifestVersion.c_str(), doc.GetAllocator());
    vDetectedLog4j.SetBool(vuln.detectedLog4j);
    vDetectedLog4j1x.SetBool(vuln.detectedLog4j1x);
    vDetectedLog4j2x.SetBool(vuln.detectedLog4j2x);
    vDetectedJNDILookupClass.SetBool(vuln.detectedJNDILookupClass);
    vDetectedLog4jManifest.SetBool(vuln.detectedLog4jManifest);
    vLog4jVendor.SetString(vuln.log4jVendor.c_str(), doc.GetAllocator());
    vLog4jVersion.SetString(vuln.log4jVersion.c_str(), doc.GetAllocator());
    vCVE20214104Mitigated.SetBool(vuln.cve20214104Mitigated);
    vCVE202144228Mitigated.SetBool(vuln.cve202144228Mitigated);
    vCVE202144832Mitigated.SetBool(vuln.cve202144832Mitigated);
    vCVE202145046Mitigated.SetBool(vuln.cve202145046Mitigated);
    vCVE202145105Mitigated.SetBool(vuln.cve202145105Mitigated);
    vCVEStatus.SetString(vuln.cveStatus.c_str(), doc.GetAllocator());

    oDetail.AddMember(L"file", vFile, doc.GetAllocator());
    oDetail.AddMember(L"manifestVendor", vManifestVendor, doc.GetAllocator());
    oDetail.AddMember(L"manifestVersion", vManifestVersion, doc.GetAllocator());
    oDetail.AddMember(L"detectedLog4j", vDetectedLog4j, doc.GetAllocator());
    oDetail.AddMember(L"detectedLog4j1x", vDetectedLog4j1x, doc.GetAllocator());
    oDetail.AddMember(L"detectedLog4j2x", vDetectedLog4j2x, doc.GetAllocator());
    oDetail.AddMember(L"detectedJNDILookupClass", vDetectedJNDILookupClass, doc.GetAllocator());
    oDetail.AddMember(L"detectedLog4jManifest", vDetectedLog4jManifest, doc.GetAllocator());
    oDetail.AddMember(L"log4jVendor", vLog4jVendor, doc.GetAllocator());
    oDetail.AddMember(L"log4jVersion", vLog4jVersion, doc.GetAllocator());
    oDetail.AddMember(L"cve20214104Mitigated", vCVE20214104Mitigated, doc.GetAllocator());
    oDetail.AddMember(L"cve202144228Mitigated", vCVE202144228Mitigated, doc.GetAllocator());
    oDetail.AddMember(L"cve202144832Mitigated", vCVE202144832Mitigated, doc.GetAllocator());
    oDetail.AddMember(L"cve202145046Mitigated", vCVE202145046Mitigated, doc.GetAllocator());
    oDetail.AddMember(L"cve202145105Mitigated", vCVE202145105Mitigated, doc.GetAllocator());
    oDetail.AddMember(L"cveStatus", vCVEStatus, doc.GetAllocator());

    oDetails.PushBack(oDetail, doc.GetAllocator());
  }

  doc.AddMember(L"scanDetails", oDetails, doc.GetAllocator());
  return rv;
}

int32_t GenerateJSONReport(bool pretty) {
  int32_t rv = ERROR_SUCCESS;
  DocumentW doc;
  rapidjson::StringBuffer buffer;

  doc.Parse(L"{}");

  GenerateReportSummary(doc);
  GenerateReportDetail(doc);

  if (pretty) {
    PrettyWriterW writer(buffer);
    doc.Accept(writer);
  } else {
    WriterW writer(buffer);
    doc.Accept(writer);
  }

  wprintf(L"%S", buffer.GetString());
  return rv;
}

int32_t GenerateSignatureReport() {
  int32_t rv = ERROR_SUCCESS;

  FILE* signature_summary = nullptr;
  _wfopen_s(&signature_summary, GetSignatureReportSummaryFilename().c_str(), L"w+, ccs=UTF-8");
  if (signature_summary) {
    fwprintf_s(signature_summary, L"scanEngine: %S\n", SCANNER_VERSION_STRING);
    fwprintf_s(signature_summary, L"scanHostname: %s\n", GetHostName().c_str());
    fwprintf_s(signature_summary, L"scanDate: %s\n", FormatLocalTime(repSummary.scanStart).c_str());
    fwprintf_s(signature_summary, L"scanDurationSeconds: %I64d\n", repSummary.scanEnd - repSummary.scanStart);
    fwprintf_s(signature_summary, L"scanErrorCount: %I64d\n", repSummary.scanErrorCount);
    fwprintf_s(signature_summary, L"scanStatus: %s\n", repSummary.scanStatus.c_str());
    fwprintf_s(signature_summary, L"scanFiles: %I64d\n", repSummary.scannedFiles);
    fwprintf_s(signature_summary, L"scannedDirectories: %I64d\n", repSummary.scannedDirectories);
    fwprintf_s(signature_summary, L"scannedCompressed: %I64d\n", repSummary.scannedCompressed);
    fwprintf_s(signature_summary, L"scannedJARS: %I64d\n", repSummary.scannedJARs);
    fwprintf_s(signature_summary, L"scannedWARS: %I64d\n", repSummary.scannedWARs);
    fwprintf_s(signature_summary, L"scannedEARS: %I64d\n", repSummary.scannedEARs);
    fwprintf_s(signature_summary, L"scannedTARS: %I64d\n", repSummary.scannedTARs);
    fwprintf_s(signature_summary, L"vulnerabilitiesFound: %I64d\n", repSummary.foundVunerabilities);
    fclose(signature_summary);
  } 

  FILE* signature_file = nullptr;
  _wfopen_s(&signature_file, GetSignatureReportFindingsFilename().c_str(), L"w+, ccs=UTF-8");
  if (signature_file) {
    for (size_t i = 0; i < repVulns.size(); i++) {
      CReportVulnerabilities vuln = repVulns[i];

      fwprintf_s(signature_file,
                 L"Source: Manifest Vendor: %s, Manifest Version: %s, JNDI Class: %s, Log4j Vendor: %s, Log4j Version: %s\n",
                 vuln.manifestVendor.c_str(),
                 vuln.manifestVersion.c_str(),
                 vuln.detectedJNDILookupClass ? L"Found" : L"NOT Found",
                 vuln.log4jVendor.c_str(),
                 vuln.log4jVersion.c_str());
      fwprintf_s(signature_file, L"Path=%s\n", vuln.file.c_str());
      fwprintf_s(signature_file, L"%s %s\n", vuln.log4jVendor.c_str(), vuln.log4jVersion.c_str());
      fwprintf_s(signature_file, L"------------------------------------------------------------------------\n");
    }

    fclose(signature_file);
  } 

  return rv;
}

int32_t AddToRemediationReport(const CReportVulnerabilities& vuln) {
  int32_t rv = ERROR_SUCCESS;

  FILE* remediation_file = nullptr;
  _wfopen_s(&remediation_file, GetRemediationReportFilename().c_str(), L"a, ccs=UTF-8");
  if (remediation_file) {
    fwprintf_s(remediation_file,
      L"Source: Signature File, Vendor: %s, Manifest Version: %s, JNDI Class: %s, Log4j Vendor: %s, Log4j Version: %s\n",
      vuln.manifestVendor.c_str(),
      vuln.manifestVersion.c_str(),
      vuln.detectedJNDILookupClass ? L"Found" : L"NOT Found",
      vuln.log4jVendor.c_str(),
      vuln.log4jVersion.c_str());
    fwprintf_s(remediation_file, L"Path=%s\n", vuln.file.c_str());
    fwprintf_s(remediation_file, L"Mitigated=%s\n", (vuln.cve202144228Mitigated && vuln.cve202145046Mitigated ? L"true": L"false"));
    fwprintf_s(remediation_file, L"------------------------------------------------------------------------\n");
    
    fclose(remediation_file);
  }

  return rv;
}

int32_t GenerateRemediationReportSummary(DocumentW& doc) {
  int32_t rv = ERROR_SUCCESS;

  ValueW vRemediationDate(rapidjson::kStringType);
  ValueW vRemediationDuration(rapidjson::kNumberType);  
  ValueW vRemediatedZIPs(rapidjson::kNumberType);
  ValueW vRemediatedJARs(rapidjson::kNumberType);
  ValueW vRemediatedWARs(rapidjson::kNumberType);
  ValueW vRemediatedEARs(rapidjson::kNumberType);  
  ValueW oSummary(rapidjson::kObjectType);

  vRemediationDate.SetString(FormatLocalTime(repSummary.scanStart).c_str(), doc.GetAllocator());
  vRemediationDuration.SetInt64(remSummary.scanEnd - remSummary.scanStart);      

  oSummary.AddMember(L"remediationDuration", vRemediationDuration, doc.GetAllocator());  
  doc.AddMember(L"remediationSummary", oSummary, doc.GetAllocator());

  return rv;
}

int32_t GenerateRemediationReportDetail(DocumentW& doc) {
  int32_t rv = ERROR_SUCCESS;
  ValueW oDetails(rapidjson::kArrayType);

  for (size_t i = 0; i < repVulns.size(); i++) {
    CReportVulnerabilities vuln = repVulns[i];

    ValueW vFile(rapidjson::kStringType);
    ValueW vManifestVendor(rapidjson::kStringType);
    ValueW vManifestVersion(rapidjson::kStringType);    
    ValueW vDetectedJNDILookupClass(rapidjson::kTrueType);    
    ValueW vLog4jVendor(rapidjson::kStringType);
    ValueW vLog4jVersion(rapidjson::kStringType);    
    ValueW vCVE202144228Mitigated(rapidjson::kTrueType);
    ValueW vCVE202145046Mitigated(rapidjson::kTrueType);        
    ValueW oDetail(rapidjson::kObjectType);

    vFile.SetString(vuln.file.c_str(), doc.GetAllocator());
    vManifestVendor.SetString(vuln.manifestVendor.c_str(), doc.GetAllocator());
    vManifestVersion.SetString(vuln.manifestVersion.c_str(), doc.GetAllocator());    
    vDetectedJNDILookupClass.SetBool(vuln.detectedJNDILookupClass);    
    vLog4jVendor.SetString(vuln.log4jVendor.c_str(), doc.GetAllocator());
    vLog4jVersion.SetString(vuln.log4jVersion.c_str(), doc.GetAllocator());    
    vCVE202144228Mitigated.SetBool(vuln.cve202144228Mitigated);
    vCVE202145046Mitigated.SetBool(vuln.cve202145046Mitigated);    

    oDetail.AddMember(L"file", vFile, doc.GetAllocator());
    oDetail.AddMember(L"manifestVendor", vManifestVendor, doc.GetAllocator());
    oDetail.AddMember(L"manifestVersion", vManifestVersion, doc.GetAllocator());    
    oDetail.AddMember(L"detectedJNDILookupClass", vDetectedJNDILookupClass, doc.GetAllocator());    
    oDetail.AddMember(L"log4jVendor", vLog4jVendor, doc.GetAllocator());
    oDetail.AddMember(L"log4jVersion", vLog4jVersion, doc.GetAllocator());    
    oDetail.AddMember(L"cve202144228Mitigated", vCVE202144228Mitigated, doc.GetAllocator());
    oDetail.AddMember(L"cve202145046Mitigated", vCVE202145046Mitigated, doc.GetAllocator());    

    oDetails.PushBack(oDetail, doc.GetAllocator());
  }

  doc.AddMember(L"remediationDetails", oDetails, doc.GetAllocator());
  return rv;
}

int32_t GenerateRemediationJSONReport(bool pretty) {
  int32_t rv = ERROR_SUCCESS;
  DocumentW doc;
  rapidjson::StringBuffer buffer;

  doc.Parse(L"{}");

  GenerateRemediationReportSummary(doc);
  GenerateRemediationReportDetail(doc);

  if (pretty) {
    PrettyWriterW writer(buffer);
    doc.Accept(writer);
  }
  else {
    WriterW writer(buffer);
    doc.Accept(writer);
  }

  wprintf(L"%S", buffer.GetString());
  return rv;
}

