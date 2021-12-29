#pragma once

class CCommandLineOptions {
 public:
  bool scanLocalDrives;
  bool scanLocalDrivesInclMountpoints;
  bool scanNetworkDrives;
  bool scanFile;
  std::wstring file;
  bool scanDirectory;
  std::wstring directory;
  bool report;
  bool reportPretty;
  bool reportSig;
  bool lowpriority;
  bool verbose;
  bool no_logo;
  bool help;

  CCommandLineOptions() {
    scanLocalDrives = false;
    scanLocalDrivesInclMountpoints = false;
    scanNetworkDrives = false;
    scanFile = false;
    file.clear();
    scanDirectory = false;
    directory.clear();
    report = false;
    reportPretty = false;
    reportSig = false;
    lowpriority = false;
    verbose = false;
    no_logo = false;
    help = false;
  }
};


extern CCommandLineOptions cmdline_options;


