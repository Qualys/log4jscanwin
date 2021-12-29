#pragma once

class CCommandLineOptions {
 public:
  bool scanLocalDrives;
  bool scanNetworkDrives;
  bool scanFile;
  std::wstring file;
  bool scanDirectory;
  std::wstring directory;
  bool report;
  bool reportPretty;
  bool reportSig;
  bool verbose;
  bool no_logo;
  bool help;
  bool lowpriority;

  CCommandLineOptions() {
    scanLocalDrives = false;
    scanNetworkDrives = false;
    scanFile = false;
    file.clear();
    scanDirectory = false;
    directory.clear();
    report = false;
    reportPretty = false;
    reportSig = false;
    verbose = false;
    no_logo = false;
    help = false;
    lowpriority = false;
  }
};


extern CCommandLineOptions cmdline_options;


