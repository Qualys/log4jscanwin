
#include "stdafx.h"
#include "Utils.h"
#include "Reports.h"
#include "Scanner.h"

#include "zlib/zlib.h"
#include "bzip2/bzlib.h"
#include "minizip/unzip.h"
#include "minizip/iowin32.h"
#include "tarlib/tarlib.h"


std::wstring GetTempporaryFilename(CScannerOptions& options) {
  wchar_t tmpPath[_MAX_PATH + 1];
  wchar_t tmpFilename[_MAX_PATH + 1];

  if (!options.tempDirectory.empty()) {
    wcscpy_s(tmpPath, options.tempDirectory.c_str());
  } else {
    GetTempPath(_countof(tmpPath), tmpPath);
  }
  GetTempFileName(tmpPath, L"qua", 0, tmpFilename);

  return std::wstring(tmpFilename);
}

int32_t CleanupTemporaryFiles(CScannerOptions& options) {
  int32_t         rv = ERROR_SUCCESS;
  WIN32_FIND_DATA FindFileData;
  HANDLE          hFind;
  std::wstring    search;
  std::wstring    filename;
  std::wstring    fullfilename;
  wchar_t         tmpPath[_MAX_PATH + 1];

  if (!options.tempDirectory.empty()) {
    wcscpy_s(tmpPath, options.tempDirectory.c_str());
  }
  else {
    GetTempPath(_countof(tmpPath), tmpPath);
  }

  search = tmpPath + std::wstring(L"qua*.tmp");

  hFind = FindFirstFile(search.c_str(), &FindFileData);
  if (hFind != INVALID_HANDLE_VALUE) {
    do {
      filename = FindFileData.cFileName;

      if ((filename.size() == 1) && (filename == L".")) continue;
      if ((filename.size() == 2) && (filename == L"..")) continue;

      std::wstring fullfilename = std::wstring(tmpPath) + filename;
      DeleteFile(fullfilename.c_str());

    } while (FindNextFile(hFind, &FindFileData));
    FindClose(hFind);
  }  else {
    rv = GetLastError();
  }

  return rv;
}

bool IsDriveExcluded(CScannerOptions& options, std::wstring drive) {
  size_t excludedDriveCount = options.excludedDrives.size();
  for (size_t i = 0; i < excludedDriveCount; ++i) {
    if (0 == _wcsnicmp(options.excludedDrives[i].c_str(), drive.c_str(), options.excludedDrives[i].size())) return true;
  }
  return false;
}

bool IsDirectoryExcluded(CScannerOptions& options, std::wstring dir) {
  size_t excludedDirectoryCount = options.excludedDirectories.size();
  for (size_t i = 0; i < excludedDirectoryCount; ++i) {
    if (0 == _wcsnicmp(options.excludedDirectories[i].c_str(), dir.c_str(), options.excludedDirectories[i].size())) return true;
  }
  return false;
}

bool IsFileExcluded(CScannerOptions& options, std::wstring file) {
  size_t excludedFileCount = options.excludedFiles.size();
  for (size_t i = 0; i < excludedFileCount; ++i) {
    if (0 == _wcsnicmp(options.excludedFiles[i].c_str(), file.c_str(), options.excludedFiles[i].size())) return true;
  }
  return false;
}

bool UncompressZIPContentsToString(unzFile zf, std::string& str) {
  int32_t rv = ERROR_SUCCESS;
  char    buf[1024];

  rv = unzOpenCurrentFile(zf);
  if (UNZ_OK == rv) {
    do {
      memset(buf, 0, sizeof(buf));
      rv = unzReadCurrentFile(zf, buf, sizeof(buf));
      if (rv < 0 || rv == 0) break;
      str.append(buf, rv);
    } while (rv > 0);
    unzCloseCurrentFile(zf);
  }

  return true;
}

bool UncompressBZIPContentsToFile(BZFILE* bzf, std::wstring file) {
  int32_t rv = ERROR_SUCCESS;
  HANDLE  h = NULL; 
  DWORD   dwBytesWritten = 0;
  char    buf[1024];

  h = CreateFile(file.c_str(), GENERIC_WRITE, NULL, NULL, CREATE_ALWAYS,
                 FILE_ATTRIBUTE_TEMPORARY, NULL);
  if (h != INVALID_HANDLE_VALUE) {
    do {
      memset(buf, 0, sizeof(buf));
      rv = BZ2_bzread(bzf, buf, sizeof(buf));
      if (rv < 0 || rv == 0) break;
      WriteFile(h, buf, rv, &dwBytesWritten, NULL);
    } while (rv > 0);
    CloseHandle(h);
  }

  return (h != INVALID_HANDLE_VALUE);
}

bool UncompressGZIPContentsToFile(gzFile gzf, std::wstring file) {
  int32_t rv = ERROR_SUCCESS;
  HANDLE  h = NULL; 
  DWORD   dwBytesWritten = 0;
  char    buf[1024];

  h = CreateFile(file.c_str(), GENERIC_WRITE, NULL, NULL, CREATE_ALWAYS,
                 FILE_ATTRIBUTE_TEMPORARY, NULL);
  if (h != INVALID_HANDLE_VALUE) {
    do {
      memset(buf, 0, sizeof(buf));
      rv = gzread(gzf, buf, sizeof(buf));
      if (rv < 0 || rv == 0) break;
      WriteFile(h, buf, rv, &dwBytesWritten, NULL);
    } while (rv > 0);
    CloseHandle(h);
  }

  return (h != INVALID_HANDLE_VALUE);
}

bool UncompressZIPContentsToFile(unzFile zf, std::wstring file) {
  int32_t rv = ERROR_SUCCESS;
  HANDLE  h = NULL;
  DWORD   dwBytesWritten = 0;
  char    buf[1024];

  h = CreateFile(file.c_str(), GENERIC_WRITE, NULL, NULL, CREATE_ALWAYS,
                 FILE_ATTRIBUTE_TEMPORARY, NULL);
  if (h != INVALID_HANDLE_VALUE) {
    rv = unzOpenCurrentFile(zf);
    if (UNZ_OK == rv) {
      do {
        memset(buf, 0, sizeof(buf));
        rv = unzReadCurrentFile(zf, buf, sizeof(buf));
        if (rv < 0 || rv == 0) break;
        WriteFile(h, buf, rv, &dwBytesWritten, NULL);
      } while (rv > 0);
      unzCloseCurrentFile(zf);
    }
    CloseHandle(h);
  }

  return (h != INVALID_HANDLE_VALUE);
}

int32_t ScanFileZIPArchive(CScannerOptions& options, std::wstring file, std::wstring file_physical) {
  int32_t         rv = ERROR_SUCCESS;
  unzFile         zf = NULL;
  unz_file_info64 file_info;
  char*           p = NULL;
  char            filename[_MAX_PATH + 1];
  std::wstring    wFilename;
  std::wstring    tmpFilename;
  bool            foundLog4j = false;
  bool            foundLog4j1x = false;
  bool            foundLog4j2x = false;
  bool            foundJNDILookupClass = false;
  bool            foundManifest = false;
  bool            foundLog4j1xPOM = false;
  bool            foundLog4j2xPOM = false;
  bool            foundLog4j2xCorePOM = false;
  bool            foundManifestVendor = false;
  bool            foundManifestVersion = false;
  bool            foundLog4jManifest = false;
  bool            cve20214104Mitigated = false;
  bool            cve202144228Mitigated = false;
  bool            cve202144832Mitigated = false;
  bool            cve202145046Mitigated = false;
  bool            cve202145105Mitigated = false;
  std::string     manifest;
  std::string     pomLog4j1x;
  std::string     pomLog4j2x;
  std::string     pomLog4j2xCore;
  std::string     manifestVendor;
  std::string     manifestVersion;
  std::string     log4jVendor;
  std::string     log4jVersion;

  zlib_filefunc64_def zfm = { 0 };
  fill_win32_filefunc64W(&zfm);

  if (!file_physical.empty()) {
    zf = unzOpen2_64(file_physical.c_str(), &zfm);
  } else {
    zf = unzOpen2_64(file.c_str(), &zfm);
  }
  if (NULL != zf) {
    ReportProcessCompressedFile();

    //
    // Check to see if there is evidence of Log4j being in the archive
    //
    rv = unzGoToFirstFile(zf);
    if (UNZ_OK == rv) {
      do {
        rv = unzGetCurrentFileInfo64(zf, &file_info, filename, _countof(filename), NULL, 0, NULL, 0);

        if (UNZ_OK == rv) {
          p = strstr(filename, "org/apache/log4j");
          if (NULL != p) {
            foundLog4j = true;
            foundLog4j1x = true;
          }
          p = strstr(filename, "org/apache/logging/log4j");
          if (NULL != p) {
            foundLog4j = true;
            foundLog4j2x = true;
          }
          if (0 == stricmp(filename, "org/apache/logging/log4j/core/lookup/JndiLookup.class")) {
            foundJNDILookupClass = true;
          }
          if (0 == stricmp(filename, "META-INF/maven/log4j/log4j/pom.properties")) {
            foundLog4j1xPOM = true;
            UncompressZIPContentsToString(zf, pomLog4j1x);
          }
          p = strstr(filename, "META-INF/maven/org.apache.logging.log4j");
          if (NULL != p) {
            if (0 == stricmp(filename, "META-INF/maven/org.apache.logging.log4j/log4j-core/pom.properties")) {
              foundLog4j2xCorePOM = true;
              UncompressZIPContentsToString(zf, pomLog4j2xCore);
            } else {
              p = strstr(filename, "/pom.properties");
              if (NULL != p) {
                foundLog4j2xPOM = true;
                UncompressZIPContentsToString(zf, pomLog4j2x);
              }
            }
          }
          if (0 == stricmp(filename, "META-INF/MANIFEST.MF")) {
            foundManifest = true;
            ReportProcessJARFile();
            UncompressZIPContentsToString(zf, manifest);
          }
          if (0 == stricmp(filename, "META-INF/application.xml")) {
            ReportProcessEARFile();
          }
          if (0 == stricmp(filename, "WEB-INF/web.xml")) {
            ReportProcessWARFile();
          }

          //
          // Add Support for nested ZIP files
          //
          wFilename = A2W(filename);
          if (IsKnownFileExtension(options.knownZipExtensions, wFilename)) {
            tmpFilename = GetTempporaryFilename(options);

            if (UncompressZIPContentsToFile(zf, tmpFilename)) {
              std::wstring masked_filename = file + L"!" + wFilename;
              std::wstring alternate_filename = tmpFilename;

              ScanFileZIPArchive(options, masked_filename, alternate_filename);
            }

            DeleteFile(tmpFilename.c_str());
          }

        }
        rv = unzGoToNextFile(zf);
      } while (UNZ_END_OF_LIST_OF_FILE != rv);
    }
    unzClose(zf);
  }
  rv = ERROR_SUCCESS;

  //
  // If we have detected some evidence of Log4j then lets check to see if we can
  // detect CVE-2021-4104, CVE-2021-44228, CVE-2021-44832, CVE-2021-45046, or CVE-2021-45105
  //
  if (foundLog4j) {
    std::string cveStatus;

    SanitizeContents(pomLog4j1x);
    SanitizeContents(pomLog4j2xCore);
    SanitizeContents(pomLog4j2x);
    SanitizeContents(manifest);

    if (foundLog4j1x) {
      GetDictionaryValue(pomLog4j1x, "artifactId=", "Unknown", log4jVendor);
      GetDictionaryValue(pomLog4j1x, "version=", "Unknown", log4jVersion);
    }
    if (foundLog4j2x) {
      if (foundLog4j2xCorePOM) {
        GetDictionaryValue(pomLog4j2xCore, "artifactId=", "Unknown", log4jVendor);
        GetDictionaryValue(pomLog4j2xCore, "version=", "Unknown", log4jVersion);
      } else {
        GetDictionaryValue(pomLog4j2x, "artifactId=", "Unknown", log4jVendor);
        GetDictionaryValue(pomLog4j2x, "version=", "Unknown", log4jVersion);
      }
    }

    if (foundManifest) {
      foundManifestVendor = GetDictionaryValue(manifest, "Implementation-Vendor-Id:", "Unknown", manifestVendor);
      if (!foundManifestVendor) {
        foundManifestVendor = GetDictionaryValue(manifest, "Implementation-Vendor:", "Unknown", manifestVendor);
        if (!foundManifestVendor) {
          foundManifestVendor = GetDictionaryValue(manifest, "Bundle-Vendor:", "Unknown", manifestVendor);
        }
      }
      foundManifestVersion = GetDictionaryValue(manifest, "Implementation-Version:", "Unknown", manifestVersion);
      if (!foundManifestVersion) {
        foundManifestVersion = GetDictionaryValue(manifest, "Bundle-Version:", "Unknown", manifestVersion);
      }

      StripWhitespace(manifestVendor);
      StripWhitespace(manifestVersion);

      if (foundManifestVendor) {
        if (std::string::npos != manifestVendor.find("log4j", 0)) {
          // 1.x
          foundLog4jManifest = true;
          manifestVendor = "log4j";
          if (log4jVendor == "Unknown") {
            log4jVendor = "log4j";
          }
        }
        if (std::string::npos != manifestVendor.find("org.apache.logging.log4j", 0)) {
          // 2.x
          foundLog4jManifest = true;
          manifestVendor = "org.apache.logging.log4j";
        }
        if (std::string::npos != manifestVendor.find("Apache Software Foundation", 0)) {
          // 1.x
          foundLog4jManifest = true;
          manifestVendor = "Apache Software Foundation";
          if (log4jVendor == "Unknown") {
            log4jVendor = "log4j";
          }
        }

        if (!foundLog4j1xPOM && !foundLog4j2xPOM && !foundLog4j2xCorePOM) {
          if (foundLog4jManifest) {
            log4jVersion = manifestVersion;
          }
        }
      }
    }

    if (foundLog4j1xPOM || foundLog4j2xPOM || foundLog4j2xCorePOM) {
      cve202144228Mitigated = IsCVE202144228Mitigated(log4jVendor, foundJNDILookupClass, log4jVersion);
      cve202144832Mitigated = IsCVE202144832Mitigated(log4jVendor, log4jVersion);
      cve202145046Mitigated = IsCVE202145046Mitigated(log4jVendor, foundJNDILookupClass, log4jVersion);
      cve202145105Mitigated = IsCVE202145105Mitigated(log4jVendor, log4jVersion);
    } else {
      if (foundLog4j1x && (foundLog4j1xPOM || foundLog4jManifest)) {
        cve20214104Mitigated = IsCVE20214104Mitigated(log4jVendor, log4jVersion);
      }
    }

    if (foundLog4j2xCorePOM && (!cve202144228Mitigated || !cve202144832Mitigated || !cve202145046Mitigated || !cve202145105Mitigated)) {

      repSummary.foundVunerabilities++;
      cveStatus = "Potentially Vulnerable (";
      cveStatus += !cve202144228Mitigated ? " CVE-2021-44228: Found" : " CVE-2021-44228: NOT Found";
      cveStatus += !cve202144832Mitigated ? " CVE-2021-44832: Found" : " CVE-2021-44832: NOT Found";
      cveStatus += !cve202145046Mitigated ? " CVE-2021-45046: Found" : " CVE-2021-45046: NOT Found";
      cveStatus += !cve202145105Mitigated ? " CVE-2021-45105: Found" : " CVE-2021-45105: NOT Found";
      cveStatus += " )";

    } else if ((foundLog4j1x && (foundLog4j1xPOM || foundLog4jManifest)) && (!cve20214104Mitigated)) {

      repSummary.foundVunerabilities++;
      cveStatus = "Potentially Vulnerable (";
      cveStatus += !cve20214104Mitigated ? " CVE-2021-4104: Found" : " CVE-2021-4104: NOT Found";
      cveStatus += " )";

    } else if (!foundJNDILookupClass && !foundManifestVendor && !foundManifestVersion) {
      cveStatus = "N/A";
    } else if (!foundJNDILookupClass && foundLog4j2x && foundLog4jManifest) {
      cveStatus = "Mitigated";
    } else if (foundJNDILookupClass && foundLog4j2x && cve202144228Mitigated && cve202144832Mitigated && cve202145046Mitigated && cve202145105Mitigated) {
      cveStatus = "Mitigated";
    } else if (!foundJNDILookupClass && foundLog4j1x && cve20214104Mitigated) {
      cveStatus = "Mitigated";
    } else if (!foundJNDILookupClass && foundLog4j1x) {
      cveStatus = "N/A";
    } else {
      cveStatus = "Unknown";
    }

    repVulns.push_back(CReportVulnerabilities(
        file, A2W(manifestVersion), A2W(manifestVendor), foundLog4j, foundLog4j1x, foundLog4j2x,
        foundJNDILookupClass, foundLog4jManifest, A2W(log4jVersion), A2W(log4jVendor), cve20214104Mitigated, 
        cve202144228Mitigated, cve202144832Mitigated, cve202145046Mitigated, cve202145105Mitigated, A2W(cveStatus)));

    if (options.console) {
      wprintf(L"Log4j Found: '%s' ( Manifest Vendor: %S, Manifest Version: %S, JNDI Class: %s, Log4j Vendor: %S, Log4j Version: %S, CVE Status: %S )\n",
              file.c_str(), manifestVendor.c_str(), manifestVersion.c_str(), foundJNDILookupClass ? L"Found" : L"NOT Found", log4jVendor.c_str(),
              log4jVersion.c_str(), cveStatus.c_str());
    }
  }

  return rv;
}

int32_t ScanFileTarball(CScannerOptions& options, std::wstring file, std::wstring file_physical) {
  int32_t           rv = ERROR_SUCCESS;
  tarlib::tarFile   tar_file;
  tarlib::tarEntry  tar_entry;
  std::wstring      tmpFilename;

  if (file_physical.size()) {
    tar_file.open(W2A(file_physical.c_str()), tarlib::tarModeRead);
  } else {
    tar_file.open(W2A(file.c_str()), tarlib::tarModeRead);
  }
  if (tar_file.is_open()) {
    ReportProcessTARFile();
    tar_entry = tar_file.get_first_entry();
    do 
    {
      if (tar_entry.header.indicator == tarlib::tarEntryNormalFile) {         
        tmpFilename = GetTempporaryFilename(options);

        std::wstring masked_filename = file + L"!" + A2W(tar_entry.header.filename);
        std::wstring alternate_filename = tmpFilename;

        if (tar_entry.extractfile_to_file(W2A(alternate_filename.c_str()))) {
          if (IsKnownFileExtension(options.knownZipExtensions, masked_filename.c_str())) {
            ReportProcessCompressedFile();
            ScanFileZIPArchive(options, masked_filename, alternate_filename);
          }
        }

        DeleteFile(tmpFilename.c_str());
      }
      tar_entry = tar_file.get_next_entry();
    } while(!tar_entry.is_empty());
  }

  return rv;
}

int32_t ScanFileCompressedBZIPTarball(CScannerOptions& options, std::wstring file, std::wstring file_physical) {
  int32_t       rv = ERROR_SUCCESS;
  BZFILE*       bzf = NULL;
  std::wstring  tmpFilename;

  if (file_physical.size()) {
    bzf = BZ2_bzopen(W2A(file_physical).c_str(), "rb");
  } else {
    bzf = BZ2_bzopen(W2A(file).c_str(), "rb");
  }
  if (NULL != bzf) {
    ReportProcessCompressedFile();
    tmpFilename = GetTempporaryFilename(options);

    if (UncompressBZIPContentsToFile(bzf, tmpFilename)) {
      ScanFileTarball(options, file, tmpFilename);
    }

    BZ2_bzclose(bzf);
    DeleteFile(tmpFilename.c_str());
  }

  return rv;
}

int32_t ScanFileCompressedGZIPTarball(CScannerOptions& options, std::wstring file, std::wstring file_physical) {
  int32_t       rv = ERROR_SUCCESS;
  gzFile        gzf = NULL;
  std::wstring  tmpFilename;

  if (file_physical.size()) {
    gzf = gzopen_w(file_physical.c_str(), "rb");
  } else {
    gzf = gzopen_w(file.c_str(), "rb");
  }
  if (NULL != gzf) {
    ReportProcessCompressedFile();
    tmpFilename = GetTempporaryFilename(options);

    if (UncompressGZIPContentsToFile(gzf, tmpFilename)) {
      ScanFileTarball(options, file, tmpFilename);
    }

    gzclose(gzf);
    DeleteFile(tmpFilename.c_str());
  }

  return rv;
}

int32_t ScanFile(CScannerOptions& options, std::wstring file, std::wstring file_physical) {
  int32_t rv = ERROR_SUCCESS;
  struct _stat64 stat;

  // Checking for excluded files
  if (IsFileExcluded(options, file)) return ERROR_NO_MORE_ITEMS;

  // Greater than desired max size?
  if (options.maxFileSize > 0) {
    if (!_wstat64(file.c_str(), &stat)) {
      if (stat.st_size > options.maxFileSize) {
        wprintf(L"Skipping File '%s' (Too large.)\n", file.c_str());
        return ERROR_FILE_TOO_LARGE;
      }
    }
  }
  

  if (options.verbose) {
    wprintf(L"Processing File '%s'\n", file.c_str());
  }

  if (0) {
  } else if (IsKnownFileExtension(options.knownZipExtensions, file)) {
    rv = ScanFileZIPArchive(options, file, file_physical);
  } else if (IsKnownFileExtension(options.knownBZipTarExtensions, file)) {
    rv = ScanFileCompressedBZIPTarball(options, file, file_physical);
  } else if (IsKnownFileExtension(options.knownGZipTarExtensions, file)) {
    rv = ScanFileCompressedGZIPTarball(options, file, file_physical);
  } else if (IsKnownFileExtension(options.knownTarExtensions, file)) {
    rv = ScanFileTarball(options, file, file_physical);
  }

  return rv;
}

int32_t ScanDirectory(CScannerOptions& options, std::wstring directory, std::wstring directory_physical) {
  int32_t         rv = ERROR_SUCCESS;
  WIN32_FIND_DATA FindFileData;
  HANDLE          hFind;
  std::wstring    search;
  std::wstring    dir;
  std::wstring    dir_phys;
  std::wstring    file;
  std::wstring    file_phys;

  // Checking for excluded directories
  if (IsDirectoryExcluded(options, directory)) return ERROR_NO_MORE_ITEMS;

  if (options.verbose) {
    wprintf(L"Processing Directory '%s'\n", directory.c_str());
  }

  if (directory_physical.size()) {
    search = directory_physical + std::wstring(L"*.*");
  } else {
    search = directory + std::wstring(L"*.*");
  }

  hFind = FindFirstFile(search.c_str(), &FindFileData);
  if (hFind != INVALID_HANDLE_VALUE) {
    do {
      std::wstring filename(FindFileData.cFileName);

      if ((filename.size() == 1) && (filename == L".")) continue;
      if ((filename.size() == 2) && (filename == L"..")) continue;
      if ((FindFileData.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) == FILE_ATTRIBUTE_REPARSE_POINT) continue;
      if ((FindFileData.dwFileAttributes & FILE_ATTRIBUTE_DEVICE) == FILE_ATTRIBUTE_DEVICE) continue;
      if ((FindFileData.dwFileAttributes & FILE_ATTRIBUTE_OFFLINE) == FILE_ATTRIBUTE_OFFLINE) continue;
      if ((FindFileData.dwFileAttributes & FILE_ATTRIBUTE_TEMPORARY) == FILE_ATTRIBUTE_TEMPORARY) continue;
      if ((FindFileData.dwFileAttributes & FILE_ATTRIBUTE_VIRTUAL) == FILE_ATTRIBUTE_VIRTUAL) continue;

      if ((FindFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == FILE_ATTRIBUTE_DIRECTORY) {

        dir = directory + filename + std::wstring(L"\\");
        if (directory_physical.size()) {
          dir_phys = directory_physical + filename + std::wstring(L"\\");
        } else {
          dir_phys.clear();
        }

        ReportProcessDirectory();

        rv = ScanDirectory(options, dir, dir_phys);
        if (ERROR_SUCCESS != rv) {
          LogErrorMessage(options.verbose, L"Failed to process directory '%s' (rv: %d)", dir.c_str(), rv);
        }

      } else {

        file = directory + filename;
        if (directory_physical.size()) {
          file_phys = directory_physical + filename;
        } else {
          file_phys.clear();
        }
        ReportProcessFile();

        rv = ScanFile(options, file, file_phys);
        if (ERROR_SUCCESS != rv) {
          LogErrorMessage(options.verbose, L"Failed to process file '%s' (rv: %d)", file.c_str(), rv);
        }

      }

    } while (FindNextFile(hFind, &FindFileData));
    FindClose(hFind);
  }  else {
    rv = GetLastError();
  }

  return rv;
}

int32_t ScanLocalDrives(CScannerOptions& options) {
  int32_t rv = ERROR_SUCCESS;
  DWORD   rt = 0;
  wchar_t drives[256];

  wcscpy_s(drives, L"");
  rt = GetLogicalDriveStrings(_countof(drives), drives);
  for (uint32_t i = 0; i < rt; i += 4) {
    wchar_t* drive = &drives[i];
    DWORD type = GetDriveType(drive);
    if ((DRIVE_FIXED == type) || (DRIVE_RAMDISK == type)) {

      // Checking for excluded drives
      if (IsDriveExcluded(options, drive)) continue;

      ScanDirectory(options, drive, L"");
    }
  }

  return rv;
}

int32_t ScanNetworkDrives(CScannerOptions& options) {
  int32_t rv = ERROR_SUCCESS;
  DWORD   rt = 0;
  wchar_t drives[256];

  wcscpy_s(drives, L"");
  rt = GetLogicalDriveStrings(_countof(drives), drives);
  for (uint32_t i = 0; i < rt; i += 4) {
    wchar_t* drive = &drives[i];
    DWORD type = GetDriveType(drive);
    if (DRIVE_REMOTE == type) {

      // Checking for excluded drives
      if (IsDriveExcluded(options, drive)) continue;

      ScanDirectory(options, drive, L"");
    }
  }

  return rv;
}

int32_t EnumMountPoints(CScannerOptions& options, std::wstring volume) {
  int32_t rv = ERROR_SUCCESS;
  HANDLE  hFindMountPoint;
  wchar_t mountPoint[MAX_PATH];

  // Find the first mount point.
  hFindMountPoint = FindFirstVolumeMountPoint(volume.c_str(), mountPoint, _countof(mountPoint));

  // If a mount point was found scan it
  if (hFindMountPoint != INVALID_HANDLE_VALUE) {
    ScanDirectory(options, (volume + mountPoint), L"");
  } else {
    if (options.verbose) {
      wprintf(L"No mount points.\n");
    }
    return rv;
  }

  // Find the next mountpoint(s)
  while (FindNextVolumeMountPoint(hFindMountPoint, mountPoint, _countof(mountPoint))) {
    ScanDirectory(options, (volume + mountPoint), L"");
  }

  FindVolumeMountPointClose(hFindMountPoint);
  return rv;
}

int32_t ScanLocalDrivesInclMountpoints(CScannerOptions& options) {
	int32_t rv = ERROR_SUCCESS;
	DWORD   rt = 0;
	wchar_t drives[256];

	wcscpy_s(drives, L"");
	rt = GetLogicalDriveStrings(_countof(drives), drives);
	for (uint32_t i = 0; i < rt; i += 4) {
		wchar_t* drive = &drives[i];
		DWORD type = GetDriveType(drive);
		if ((DRIVE_FIXED == type) || (DRIVE_RAMDISK == type)) {

      // Checking for excluded drives
      if (IsDriveExcluded(options, drive)) continue;

      ScanDirectory(options, drive, L"");

			// Enumerate mount points on the drive and scan them
			EnumMountPoints(options, drive);
		}
	}

	return rv;
}

int32_t ScanPrepareEnvironment(CScannerOptions& options) {
  int32_t rv = ERROR_SUCCESS;
  rv = CleanupTemporaryFiles(options);
  return rv;
}
