
#include "stdafx.h"
#include "Utils.h"
#include "Reports.h"
//#include "Main.h"

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

int32_t GenerateReportSummary(DocumentW& doc) {
  int32_t rv = ERROR_SUCCESS;

  ValueW vScanDate(rapidjson::kStringType);
  ValueW vScanDuration(rapidjson::kNumberType);
  ValueW vScannedFiles(rapidjson::kNumberType);
  ValueW vScannedDirectories(rapidjson::kNumberType);
  ValueW vScannedJARs(rapidjson::kNumberType);
  ValueW vScannedWARs(rapidjson::kNumberType);
  ValueW vScannedEARs(rapidjson::kNumberType);
  ValueW vScannedZIPs(rapidjson::kNumberType);
  ValueW vVulnerabilitiesFound(rapidjson::kNumberType);
  ValueW oSummary(rapidjson::kObjectType);

  wchar_t buf[64] = {0};
  struct tm* tm = NULL;

  tm = localtime((time_t*)&repSummary.scanStart);
  wcsftime(buf, _countof(buf) - 1, L"%FT%T%z", tm);

  vScanDate.SetString(&buf[0], doc.GetAllocator());
  vScanDuration.SetInt64(repSummary.scanEnd - repSummary.scanStart);
  vScannedFiles.SetInt64(repSummary.scannedFiles);
  vScannedDirectories.SetInt64(repSummary.scannedDirectories);
  vScannedJARs.SetInt64(repSummary.scannedJARs);
  vScannedWARs.SetInt64(repSummary.scannedWARs);
  vScannedEARs.SetInt64(repSummary.scannedEARs);
  vScannedZIPs.SetInt64(repSummary.scannedZIPs);
  vVulnerabilitiesFound.SetInt64(repSummary.foundVunerabilities);

  oSummary.AddMember(L"scanDuration", vScanDuration, doc.GetAllocator());
  oSummary.AddMember(L"scannedFiles", vScannedFiles, doc.GetAllocator());
  oSummary.AddMember(L"scannedDirectories", vScannedDirectories,
                     doc.GetAllocator());
  oSummary.AddMember(L"scannedJARs", vScannedJARs, doc.GetAllocator());
  oSummary.AddMember(L"scannedWARs", vScannedWARs, doc.GetAllocator());
  oSummary.AddMember(L"scannedEARs", vScannedEARs, doc.GetAllocator());
  oSummary.AddMember(L"scannedZIPs", vScannedZIPs, doc.GetAllocator());
  oSummary.AddMember(L"vulnerabilitiesFound", vVulnerabilitiesFound,
                     doc.GetAllocator());

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

  // signature output should go into a file always
  // 1. First check if %programdata%\Qualys\QualysAgent exist
  // 2. If not exist then current direcotry will be used

  FILE* signature_file = nullptr;
  _wfopen_s(&signature_file, GetSignatureReportFilename().c_str(), L"w+, ccs=UTF-8");

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

  wchar_t buf[64] = { 0 };
  struct tm* tm = NULL;

  tm = localtime((time_t*)&remSummary.scanStart);
  wcsftime(buf, _countof(buf) - 1, L"%FT%T%z", tm);

  vRemediationDate.SetString(&buf[0], doc.GetAllocator());
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