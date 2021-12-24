// Main.cpp : This file contains the 'main' function. Program
// execution begins and ends there.
//

#include "stdafx.h"
#include "Utils.h"
#include "Reports.h"
#include "Scanner.h"
#include "Remediate.h"
#include "MainRemediate.h"

#include "Version.info"


#define ARGX3(s1, s2, s3) \
  (!_wcsicmp(argv[i], s1) || !_wcsicmp(argv[i], s2) || !_wcsicmp(argv[i], s3))
#define ARG(S) ARGX3(L"-" #S, L"--" #S, L"/" #S)
#define ARGPARAMCOUNT(X) ((i + X) <= (argc - 1))


CCommandLineOptions cmdline_options;


int32_t PrintHelp(int32_t argc, wchar_t* argv[]) {
  int32_t rv = ERROR_SUCCESS;

  wprintf(L"/remediate_file \"C:\\Some\\Path.[jar|war|ear|zip]\n");
  wprintf(L"  Remove JndiLookup.class from specified JAR, WAR, EAR, ZIP files.\n");
  wprintf(L"/remediate_sig\n");
  wprintf(L"  Remove JndiLookup.class from JAR, WAR, EAR, ZIP files detected by scanner utility\n");  
  wprintf(L"/report\n");
  wprintf(L"  Generate a JSON for mitigations of supported CVE(s).\n");
  wprintf(L"/report_pretty\n");
  wprintf(L"  Generate a pretty JSON for mitigations of supported CVE(s).\n");
  wprintf(L"\n");

  return rv;
}

int32_t ProcessCommandLineOptions(int32_t argc, wchar_t* argv[]) {
  int32_t rv = ERROR_SUCCESS;

  for (int32_t i = 1; i < argc; i++) {
    if (0) {
    } else if (ARG(remediate_file)) {
      cmdline_options.remediateFile = true;
      cmdline_options.file = argv[i + 1];
    } else if (ARG(remediate_sig)) {
      cmdline_options.remediateSig = true;      
      cmdline_options.no_logo = true;
    } else if (ARG(report)) {
      cmdline_options.report = true;      
    } else if (ARG(report_pretty)) {
      cmdline_options.report = true;
      cmdline_options.report_pretty = true;
    }
    else if (ARG(nologo)) {
      cmdline_options.no_logo = true;
    } else if (ARG(v) || ARG(verbose)) {
      cmdline_options.verbose = true;
    } else if (ARG(?) || ARG(h) || ARG(help)) {
      cmdline_options.help = true;
    }
  }

  //
  // Check to make sure the directory path is normalized
  //
  if (cmdline_options.remediateFile) {
    if ((0 == cmdline_options.file.substr(0, 1).compare(L"\"")) ||
        (0 == cmdline_options.file.substr(0, 1).compare(L"'"))) {
      cmdline_options.file.erase(0, 1);
    }
    if ((0 == cmdline_options.file.substr(cmdline_options.file.size() - 1, 1).compare(L"\"")) ||
        (0 == cmdline_options.file.substr(cmdline_options.file.size() - 1, 1).compare(L"'"))) {
      cmdline_options.file.erase(cmdline_options.file.size() - 1, 1);
    }    
  }

  return rv;
}

int32_t __cdecl wmain(int32_t argc, wchar_t* argv[]) {
  int32_t rv = ERROR_SUCCESS;

  SetUnhandledExceptionFilter(CatchUnhandledExceptionFilter);
  _setmode(_fileno(stdout), _O_U16TEXT);

#ifndef _WIN64
  using typeWow64DisableWow64FsRedirection = BOOL(WINAPI*)(PVOID OlValue);
  typeWow64DisableWow64FsRedirection Wow64DisableWow64FsRedirection;
  BOOL bIs64BitWindows = FALSE;
  PVOID pHandle{};

  if (!IsWow64Process(GetCurrentProcess(), &bIs64BitWindows)) {
    wprintf(L"Failed to determine if process is running as WoW64.\n");
    goto END;
  }

  if (bIs64BitWindows) {
    Wow64DisableWow64FsRedirection =
        (typeWow64DisableWow64FsRedirection)GetProcAddress(
            GetModuleHandle(L"Kernel32.DLL"), "Wow64DisableWow64FsRedirection");

    if (Wow64DisableWow64FsRedirection) {
      Wow64DisableWow64FsRedirection(&pHandle);
    }
  }
#endif

  rv = ProcessCommandLineOptions(argc, argv);
  if (ERROR_SUCCESS != rv) {
    wprintf(L"Failed to process command line options.\n");
    goto END;
  }

  if (!cmdline_options.no_logo) {
    wprintf(L"Qualys Log4j Remediation Utility %S\n", VERSION_STRING);
    wprintf(L"https://www.qualys.com/\n");
    wprintf(L"Supported CVE(s): CVE-2021-44228, CVE-2021-45046\n\n");
  }

  if (cmdline_options.help) {
    PrintHelp(argc, argv);
    goto END;
  }

  if (cmdline_options.remediateSig) {
    OpenStatusFile(GetRemediationStatusFilename());
  }

  remSummary.scanStart = time(0);

  if (cmdline_options.remediateSig) {
    wchar_t buf[64] = {0};
    struct tm* tm = NULL;

    tm = localtime((time_t*)&remSummary.scanStart);
    wcsftime(buf, _countof(buf) - 1, L"%FT%T%z", tm);

    LogStatusMessage(L"Remediation start time : %s\n", buf);
  }

  // Add handlers here
  if (cmdline_options.remediateSig) {
    rv = RemediateFromSignatureReport();
    if (rv != ERROR_SUCCESS) {
      LogStatusMessage(L"Failed to remediate vulnerabilities from signature report.\n");
    }
  }
  else if (cmdline_options.remediateFile) {
    RemediateLog4J remediator;
    rv = remediator.RemediateFileArchive(cmdline_options.file);
    if(rv != ERROR_SUCCESS){
      LogStatusMessage(L"Failed to remediate file: %s\n", cmdline_options.file.c_str());
    }
  }

  remSummary.scanEnd = time(0);

  if (cmdline_options.remediateSig) {
    wchar_t buf[64] = {0};
    struct tm* tm = NULL;

    tm = localtime((time_t*)&remSummary.scanEnd);
    wcsftime(buf, _countof(buf) - 1, L"%FT%T%z", tm);

    LogStatusMessage(L"Remediation end time : %s\n", buf);
  }

  if (!cmdline_options.no_logo) {
    wchar_t buf[64] = {0};
    struct tm* tm = NULL;

    tm = localtime((time_t*)&remSummary.scanEnd);
    wcsftime(buf, _countof(buf) - 1, L"%FT%T%z", tm);

    wprintf(L"\tRemediation Summary:\n");
    wprintf(L"\tRemediation Date:\t\t %s\n", buf);
    wprintf(L"\tRemediation Duration:\t\t %lld Seconds\n", remSummary.scanEnd - remSummary.scanStart);    
    wprintf(L"\tJAR(s) Remediated:\t\t %lld\n", remSummary.remediatedJARs);
    wprintf(L"\tWAR(s) Remediated:\t\t %lld\n", remSummary.remediatedWARs);
    wprintf(L"\tEAR(s) Remediated:\t\t %lld\n", remSummary.remediatedEARs);
    wprintf(L"\tZIP(s) Remediated:\t\t %lld\n", remSummary.remediatedZIPs);
  }

  if (cmdline_options.report) {
    GenerateRemediationJSONReport(cmdline_options.report_pretty);
  }

END:

  if (cmdline_options.remediateSig) {
    if (error_array.empty()) {
      LogStatusMessage(L"\nRun status : Success\n");
      LogStatusMessage(L"Result file location : %s\n", GetRemediationReportFilename().c_str());
    } else {
      LogStatusMessage(L"\nRun status : Partially Successful\n");
      LogStatusMessage(L"Result file location : %s\n", GetRemediationReportFilename().c_str());

      LogStatusMessage(L"Errors :\n");
      for (const auto& e : error_array) {
        LogStatusMessage(L"%s\n", e.c_str());
      }
    }
  }

  CloseStatusFile();

  return rv;
}
