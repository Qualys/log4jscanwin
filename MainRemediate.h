#pragma once

class CCommandLineOptions {
 public:
  bool remediateFile;
  bool remediateSig;
  std::wstring file;  
  bool report;
  bool report_pretty;
  bool verbose;
  bool no_logo;
  bool help;

  CCommandLineOptions() {
    remediateFile = false;
    remediateSig = false;
    file.clear();    
    report = false;
    report_pretty = false;
    verbose = false;
    no_logo = false;
    help = false;
  }
};

extern CCommandLineOptions cmdline_options;
