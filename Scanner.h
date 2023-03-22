#pragma once

class CScannerOptions {
public:
  bool console;
  bool verbose;
  std::vector<std::wstring> excludedDrives;
  std::vector<std::wstring> excludedDirectories;
  std::vector<std::wstring> excludedFiles;
  int64_t maxFileSize;
  std::wstring tempDirectory;
  std::vector<std::wstring> knownTarExtensions;
  std::vector<std::wstring> knownGZipTarExtensions;
  std::vector<std::wstring> knownBZipTarExtensions;
  std::vector<std::wstring> knownZipExtensions;

  CScannerOptions() {
    console = false;
    verbose = false;
    excludedDrives.clear();
    excludedDirectories.clear();
    excludedFiles.clear();
    maxFileSize = 0;
    tempDirectory.clear();
    knownTarExtensions.clear();
    knownGZipTarExtensions.clear();
    knownBZipTarExtensions.clear();
    knownZipExtensions.clear();
  }
};

int32_t ScanFile(CScannerOptions& options, std::wstring file, std::wstring file_physical);
int32_t ScanDirectory(CScannerOptions& options, std::wstring directory, std::wstring directory_physical);
int32_t ScanLocalDrives(CScannerOptions& options);
int32_t ScanNetworkDrives(CScannerOptions& options);
int32_t ScanLocalDrivesInclMountpoints(CScannerOptions& options);
int32_t ScanPrepareEnvironment(CScannerOptions& options);
