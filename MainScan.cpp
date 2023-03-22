// Main.cpp : This file contains the 'main' function. Program
// execution begins and ends there.
//

#include "stdafx.h"
#include "Utils.h"
#include "Reports.h"
#include "Scanner.h"
#include "Version.info"

#include "rapidjson/rapidjson.h"
#include "zlib/zlib.h"
#include "bzip2/bzlib.h"
#include "tarlib/tarlib.h"


struct CCommandLineOptions {
 public:
  bool scanLocalDrives{ false };
  bool scanLocalDrivesInclMountpoints{ false };
  bool scanNetworkDrives{ false };
  bool scanFile{ false };
  bool scanDirectory{ false };
  std::wstring file;
  std::wstring directory;
  std::vector<std::wstring> excludedDrives;
  std::vector<std::wstring> excludedDirectories;
  std::vector<std::wstring> excludedFiles;
  int64_t maxFileSize{ 0 };
  std::wstring tempDirectory;
  bool report{ false };
  bool reportPretty{ false };
  bool reportSig{ false };
  bool lowpriority{ false };
  bool verbose{ false };
  bool no_logo{ false };
  bool help{ false };

  std::vector<std::wstring> knownTarExtensions{
    L".tar"
  };

  std::vector<std::wstring> knownGZipTarExtensions{
    L".tgz",
    L".tar.gz"
  };

  std::vector<std::wstring> knownBZipTarExtensions{
    L".tbz",
    L".tbz2",
    L".tar.bz",
    L".tar.bz2"
  };

  std::vector<std::wstring> knownZipExtensions{
    L".zip",
    L".jar",
    L".war",
    L".ear",
    L".par",
    L".kar",
    L".sar",
    L".rar",
    L".jpi",
    L".hpi",
    L".apk"
  };
};

CCommandLineOptions cmdline_options;


int32_t PrintHelp(int32_t argc, wchar_t* argv[]) {
  int32_t rv = ERROR_SUCCESS;

  wprintf(L"/scan\n");
  wprintf(L"  Scan local drives for vulnerable files used by various Java applications.\n");
  wprintf(L"/scan_network\n");
  wprintf(L"  Scan network drives for vulnerable files used by various Java applications.\n");
  wprintf(L"/scan_directory \"C:\\Some\\Path\"\n");
  wprintf(L"  Scan a specific directory for vulnerable files used by various Java applications.\n");
  wprintf(L"/scan_file \"C:\\Some\\Path\\Some.jar\"\n");
  wprintf(L"  Scan a specific file for supported CVE(s).\n");
  wprintf(L"/scaninclmountpoints\n");
  wprintf(L"  Scan local drives including mount points for vulnerable files used by various Java applications.\n");
  wprintf(L"/max_size X\n");
  wprintf(L"  Skip scanning files which are larger than X megabytes in size.\n");
  wprintf(L"/temp_directory \"C:\\Temp\"\n");
  wprintf(L"  Use the desired directory for storing temporary files.\n");
  wprintf(L"/exclude_drive \"C:\\\"\n");
  wprintf(L"  Exclude a drive from the scan.\n");
  wprintf(L"/exclude_directory \"C:\\Some\\Path\"\n");
  wprintf(L"  Exclude a directory from a scan.\n");
  wprintf(L"/exclude_file \"C:\\Some\\Path\\Some.jar\"\n");
  wprintf(L"  Exclude a file from a scan.\n");
  wprintf(L"/knownTarExtension \".tar\"\n");
  wprintf(L"/knownGZipTarExtension \".tgz\"\n");
  wprintf(L"/knownBZipTarExtension \".tbz\"\n");
  wprintf(L"/knownZipExtension \".jar\"\n");
  wprintf(L"  Add additional file type extensions to the scanner.\n");
  wprintf(L"/report\n");
  wprintf(L"  Generate a JSON report of possible detections of supported CVE(s).\n");
  wprintf(L"/report_pretty\n");
  wprintf(L"  Generate a human readable JSON report of possible detections of supported CVE(s).\n");
  wprintf(L"/report_sig\n");
  wprintf(L"  Generate a signature report of possible detections of supported CVE(s).\n");
  wprintf(L"/lowpriority\n");
  wprintf(L"  Lowers the execution and I/O priority of the scanner.\n");
  wprintf(L"/help\n");
  wprintf(L"  Displays this help page.\n");
  wprintf(L"\n");

  return rv;
}

int32_t ProcessCommandLineOptions(int32_t argc, wchar_t* argv[]) {
  int32_t rv = ERROR_SUCCESS;
  std::wstring  str;

  for (int32_t i = 1; i < argc; i++) {
    if (0) {
    } else if (ARG(scan)) {
      cmdline_options.scanLocalDrives = true;
    } else if (ARG(scan_network)) {
      cmdline_options.scanNetworkDrives = true;
    } else if (ARG(scan_file) && ARGPARAMCOUNT(1)) {
      cmdline_options.scanFile = true;
      str = argv[i + 1];
      if (NormalizeFileName(str)) {
        cmdline_options.file = str;
      }
    } else if (ARG(scan_directory) && ARGPARAMCOUNT(1)) {
      cmdline_options.scanDirectory = true;
      str = argv[i + 1];
      if (NormalizeDirectoryName(str)) {
        cmdline_options.directory = str;
      }
    } else if (ARG(max_size) && ARGPARAMCOUNT(1)) {
      cmdline_options.maxFileSize = _wtoi(argv[i + 1]) * 1024 * 1024;
    } else if (ARG(temp_directory) && ARGPARAMCOUNT(1)) {
      str = argv[i + 1];
      if (NormalizeDirectoryName(str)) {
        cmdline_options.tempDirectory = str;
      }
    } else if (ARG(scaninclmountpoints)) {
      cmdline_options.scanLocalDrivesInclMountpoints = true;
    } else if (ARG(exclude_file) && ARGPARAMCOUNT(1)) {
      str = argv[i + 1];
      if (NormalizeFileName(str)) {
        cmdline_options.excludedFiles.push_back(str);
      }
    } else if (ARG(exclude_directory) && ARGPARAMCOUNT(1)) {
      str = argv[i + 1];
      if (NormalizeDirectoryName(str)) {
        cmdline_options.excludedDirectories.push_back(str);
      }
    } else if (ARG(exclude_drive) && ARGPARAMCOUNT(1)) {
      str = argv[i + 1];
      if (NormalizeDriveName(str)) {
        cmdline_options.excludedDrives.push_back(str);
      }
    } else if (ARG(knownTarExtension) && ARGPARAMCOUNT(1)) {
      str = argv[i + 1];
      if (NormalizeFileExtension(str)) {
        cmdline_options.knownTarExtensions.push_back(str);
      }
    } else if (ARG(knownGZipTarExtension) && ARGPARAMCOUNT(1)) {
      str = argv[i + 1];
      if (NormalizeFileExtension(str)) {
        cmdline_options.knownGZipTarExtensions.push_back(str);
      }
    } else if (ARG(knownBZipTarExtension) && ARGPARAMCOUNT(1)) {
      str = argv[i + 1];
      if (NormalizeFileExtension(str)) {
        cmdline_options.knownBZipTarExtensions.push_back(str);
      }
    } else if (ARG(knownZipExtension) && ARGPARAMCOUNT(1)) {
      str = argv[i + 1];
      if (NormalizeFileExtension(str)) {
        cmdline_options.knownZipExtensions.push_back(str);
      }
    } else if (ARG(report)) {
      cmdline_options.no_logo = true;
      cmdline_options.report = true;
    } else if (ARG(report_pretty)) {
      cmdline_options.no_logo = true;
      cmdline_options.reportPretty = true;
    } else if (ARG(report_sig)) {
      cmdline_options.no_logo = true;
      cmdline_options.reportSig = true;
    } else if (ARG(nologo)) {
      cmdline_options.no_logo = true;
    } else if (ARG(lowpriority)) {
      cmdline_options.lowpriority = true;
    } else if (ARG(v) || ARG(verbose)) {
      cmdline_options.verbose = true;
    } else if (ARG(?) || ARG(h) || ARG(help)) {
      cmdline_options.help = true;
    }
  }

  return rv;
}

int32_t __cdecl wmain(int32_t argc, wchar_t* argv[]) {
  int32_t rv = ERROR_SUCCESS;
  CScannerOptions options;

  SetUnhandledExceptionFilter(CatchUnhandledExceptionFilter);
  _setmode(_fileno(stdout), _O_U16TEXT);

#ifndef _WIN64
  using typeWow64DisableWow64FsRedirection = BOOL(WINAPI*)(PVOID OlValue);
  typeWow64DisableWow64FsRedirection Wow64DisableWow64FsRedirection;
  BOOL bIs64BitWindows = FALSE;
  PVOID pHandle;

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
    wprintf(L"Qualys Log4j Vulnerability Scanner %S\n", SCANNER_VERSION_STRING);
    wprintf(L"https://www.qualys.com/\n");
    wprintf(L"Dependencies: minizip/1.1 zlib/%S, bzip2/%S, rapidjson/%S\n", zlibVersion(), BZ2_bzlibVersion(), RAPIDJSON_VERSION_STRING);
    wprintf(L"Supported CVE(s): CVE-2021-4104, CVE-2021-44228, CVE-2021-44832, CVE-2021-45046, CVE-2021-45105\n\n");
  }

  if (cmdline_options.help) {
    PrintHelp(argc, argv);
    goto END;
  }

  if (!cmdline_options.scanLocalDrives && !cmdline_options.scanNetworkDrives &&
      !cmdline_options.scanDirectory && !cmdline_options.scanFile &&
      !cmdline_options.scanLocalDrivesInclMountpoints) {
    cmdline_options.scanLocalDrives = true;
  }

  if (cmdline_options.reportSig) {
    OpenStatusFile(GetSignatureStatusFilename());
  }
  
  if (cmdline_options.lowpriority) {
    SetThreadPriority(GetCurrentThread(), THREAD_MODE_BACKGROUND_BEGIN);
    if (!SetPriorityClass(GetCurrentProcess(), PROCESS_MODE_BACKGROUND_BEGIN))
    {
      wprintf(L"Failed to set process priority.\n\n");
    }
    else
    {
      if (cmdline_options.verbose) {
        wprintf(L"CPU and I/O priority lowered.\n\n");
      }
    }
  }

  //
  // Configure Scanner Options
  //
  options.console = !cmdline_options.no_logo;
  options.verbose = cmdline_options.verbose;
  options.excludedDrives = cmdline_options.excludedDrives;
  options.excludedDirectories = cmdline_options.excludedDirectories;
  options.excludedFiles = cmdline_options.excludedFiles;
  options.knownTarExtensions = cmdline_options.knownTarExtensions;
  options.knownGZipTarExtensions = cmdline_options.knownGZipTarExtensions;
  options.knownBZipTarExtensions = cmdline_options.knownBZipTarExtensions;
  options.knownZipExtensions = cmdline_options.knownZipExtensions;
  options.maxFileSize = cmdline_options.maxFileSize;
  options.tempDirectory = cmdline_options.tempDirectory;

  //
  // Configure Reports
  //
  repSummary.excludedDrives = cmdline_options.excludedDrives;
  repSummary.excludedDirectories = cmdline_options.excludedDirectories;
  repSummary.excludedFiles = cmdline_options.excludedFiles;
  repSummary.knownTarExtensions = cmdline_options.knownTarExtensions;
  repSummary.knownGZipTarExtensions = cmdline_options.knownGZipTarExtensions;
  repSummary.knownBZipTarExtensions = cmdline_options.knownBZipTarExtensions;
  repSummary.knownZipExtensions = cmdline_options.knownZipExtensions;

  //
  // Report Configured Options
  //
  if (!cmdline_options.no_logo && cmdline_options.knownTarExtensions.size()) {
    wprintf(L"Known TAR Extensions\t\t: ");
    for (size_t i = 0; i < cmdline_options.knownTarExtensions.size(); ++i) {
      if ((cmdline_options.knownTarExtensions.size() == 1) ||
          (cmdline_options.knownTarExtensions.size() - 1 == i)) {
        wprintf(L"%s", cmdline_options.knownTarExtensions[i].c_str());
      } else {
        wprintf(L"%s, ", cmdline_options.knownTarExtensions[i].c_str());
      }
    }
    wprintf(L"\n");
  }
  if (!cmdline_options.no_logo && cmdline_options.knownGZipTarExtensions.size()) {
    wprintf(L"Known GZIP TAR Extensions\t: ");
    for (size_t i = 0; i < cmdline_options.knownGZipTarExtensions.size(); ++i) {
      if ((cmdline_options.knownGZipTarExtensions.size() == 1) ||
          (cmdline_options.knownGZipTarExtensions.size()-1 == i)) {
        wprintf(L"%s", cmdline_options.knownGZipTarExtensions[i].c_str());
      } else {
        wprintf(L"%s, ", cmdline_options.knownGZipTarExtensions[i].c_str());
      }
    }
    wprintf(L"\n");
  }
  if (!cmdline_options.no_logo && cmdline_options.knownBZipTarExtensions.size()) {
    wprintf(L"Known BZIP TAR Extensions\t: ");
    for (size_t i = 0; i < cmdline_options.knownBZipTarExtensions.size(); ++i) {
      if ((cmdline_options.knownBZipTarExtensions.size() == 1) ||
          (cmdline_options.knownBZipTarExtensions.size()-1 == i)) {
        wprintf(L"%s", cmdline_options.knownBZipTarExtensions[i].c_str());
      } else {
        wprintf(L"%s, ", cmdline_options.knownBZipTarExtensions[i].c_str());
      }
    }
    wprintf(L"\n");
  }
  if (!cmdline_options.no_logo && cmdline_options.knownZipExtensions.size()) {
    wprintf(L"Known ZIP Extensions\t\t: ");
    for (size_t i = 0; i < cmdline_options.knownZipExtensions.size(); ++i) {
      if ((cmdline_options.knownZipExtensions.size() == 1) ||
          (cmdline_options.knownZipExtensions.size()-1 == i)) {
        wprintf(L"%s", cmdline_options.knownZipExtensions[i].c_str());
      } else {
        wprintf(L"%s, ", cmdline_options.knownZipExtensions[i].c_str());
      }
    }
    wprintf(L"\n");
  }
  if (!cmdline_options.no_logo && cmdline_options.excludedDrives.size()) {
    wprintf(L"Excluding Drives:\n");
    for (size_t i = 0; i < cmdline_options.excludedDrives.size(); ++i) {
      wprintf(L"\t%s\n", cmdline_options.excludedDrives[i].c_str());
    }
    wprintf(L"\n");
  }
  if (!cmdline_options.no_logo && cmdline_options.excludedDirectories.size()) {
    wprintf(L"Excluding Directories:\n");
    for (size_t i = 0; i < cmdline_options.excludedDirectories.size(); ++i) {
      wprintf(L"\t%s\n", cmdline_options.excludedDirectories[i].c_str());
    }
    wprintf(L"\n");
  }
  if (!cmdline_options.no_logo && cmdline_options.excludedFiles.size()) {
    wprintf(L"Excluding Files:\n");
    for (size_t i = 0; i < cmdline_options.excludedFiles.size(); ++i) {
      wprintf(L"\t%s\n", cmdline_options.excludedFiles[i].c_str());
    }
    wprintf(L"\n");
  }
  if (!cmdline_options.no_logo) {
    wprintf(L"\n");
  }

  //
  // Scan Started
  //
  ScanPrepareEnvironment(options);

  repSummary.scanStart = time(0);

  if (cmdline_options.reportSig) {
    LogStatusMessage(L"Scan Start: %s", FormatLocalTime(repSummary.scanStart).c_str());
  }

  if (cmdline_options.scanLocalDrives) {
    if (!cmdline_options.no_logo) {
      wprintf(L"Scanning Local Drives...\n");
    }
    ScanLocalDrives(options);
  }
  
  if (cmdline_options.scanLocalDrivesInclMountpoints) {
     if (!cmdline_options.no_logo) {
       wprintf(L"Scanning Local Drives including Mountpoints...\n");
      }
      ScanLocalDrivesInclMountpoints(options);
  }
  
  if (cmdline_options.scanNetworkDrives) {
    if (!cmdline_options.no_logo) {
      wprintf(L"Scanning Network Drives...\n");
    }
    ScanNetworkDrives(options);
  }

  if (cmdline_options.scanDirectory) {
    if (!cmdline_options.no_logo) {
      wprintf(L"Scanning '%s'...\n", cmdline_options.directory.c_str());
    }
    ScanDirectory(options, cmdline_options.directory, L"");
  }

  if (cmdline_options.scanFile) {
    if (!cmdline_options.no_logo) {
      wprintf(L"Scanning '%s'...\n", cmdline_options.file.c_str());
    }
    ScanFile(options, cmdline_options.file, L"");
  }

  repSummary.scanEnd = time(0);
  repSummary.scanErrorCount = error_array.size();
  if (error_array.empty()) {
    repSummary.scanStatus = L"Success";
  } else {
    repSummary.scanStatus = L"Partially Successful";
  }

  //
  // Scan Completed
  //

  if (cmdline_options.lowpriority) {
    SetPriorityClass(GetCurrentProcess(), PROCESS_MODE_BACKGROUND_END);
    SetThreadPriority(GetCurrentThread(), THREAD_MODE_BACKGROUND_END);
  }
  
  if (cmdline_options.reportSig) {
    LogStatusMessage(L"\nScan End: %s", FormatLocalTime(repSummary.scanEnd).c_str());
  }


  if (!cmdline_options.no_logo) {
    wprintf(L"\nScan Summary:\n");
    wprintf(L"\tScan Date:\t\t\t %s\n", FormatLocalTime(repSummary.scanStart).c_str());
    wprintf(L"\tScan Duration:\t\t\t %lld Seconds\n", repSummary.scanEnd - repSummary.scanStart);
    wprintf(L"\tScan Error Count:\t\t %I64d\n", repSummary.scanErrorCount);
    wprintf(L"\tScan Status:\t\t\t %s\n", repSummary.scanStatus.c_str());
    wprintf(L"\tFiles Scanned:\t\t\t %lld\n", repSummary.scannedFiles);
    wprintf(L"\tDirectories Scanned:\t\t %lld\n", repSummary.scannedDirectories);
    wprintf(L"\tCompressed File(s) Scanned:\t %lld\n", repSummary.scannedCompressed);
    wprintf(L"\tJAR(s) Scanned:\t\t\t %lld\n", repSummary.scannedJARs);
    wprintf(L"\tWAR(s) Scanned:\t\t\t %lld\n", repSummary.scannedWARs);
    wprintf(L"\tEAR(s) Scanned:\t\t\t %lld\n", repSummary.scannedEARs);
    wprintf(L"\tTAR(s) Scanned:\t\t\t %lld\n", repSummary.scannedTARs);
    wprintf(L"\tVulnerabilities Found:\t\t %lld\n", repSummary.foundVunerabilities);
  }

  if (cmdline_options.report) {
    GenerateJSONReport(cmdline_options.reportPretty);
  }
  if (cmdline_options.reportSig) {
    GenerateSignatureReport();
  }

END:

  if (cmdline_options.reportSig) {
    LogStatusMessage(L"Result File: %s", GetSignatureReportFindingsFilename().c_str());
    LogStatusMessage(L"Summary File: %s", GetSignatureReportSummaryFilename().c_str());
    LogStatusMessage(L"Run Status: %s", repSummary.scanStatus.c_str());
    if (repSummary.scanErrorCount) {
      LogStatusMessage(L"Errors :");
      for (const auto& e : error_array) {
        LogStatusMessage(L"%s", e.c_str());
      }
    }
  }

  CloseStatusFile();

  return rv;
}
