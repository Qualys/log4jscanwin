
#include "stdafx.h"
#include "Utils.h"
#include "Reports.h"
//#include "Main.h"
#include "Scanner.h"

#include "minizip/unzip.h"
#include "minizip/iowin32.h"
#include "zlib/zlib.h"


bool UncompressContents(unzFile zf, std::string& str) {
  int32_t rv = ERROR_SUCCESS;
  char buf[4096];

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

bool ParseVersion(std::string version, int& major, int& minor, int& build) {
  return ( 0 != sscanf(version.c_str(), "%d.%d.%d", &major, &minor, &build) );
}

bool IsCVE20214104Mitigated(std::string log4jVendor, std::string version) {
  int major = 0, minor = 0, build = 0;
  if (log4jVendor.compare("log4j") != 0) return true;
  if (ParseVersion(version, major, minor, build)) {
    if ((major >= 2) || (major < 1)) return true;
    if ((major == 1) && (minor <= 1)) return true;
    if ((major == 1) && (minor == 2) && (build >= 17)) return true;
    if ((major == 1) && (minor >= 3)) return true;
  }
  return false;
}

bool IsCVE202144228Mitigated(std::string log4jVendor, bool foundJNDILookupClass, std::string version) {
  int major = 0, minor = 0, build = 0;
  if (!foundJNDILookupClass) return true;
  if (log4jVendor.compare("log4j-core") != 0) return true;
  if (ParseVersion(version, major, minor, build)) {
    if (major < 2) return true;
    if ((major == 2) && (minor == 12) && (build >= 2)) return true;
    if ((major == 2) && (minor >= 15)) return true;
  }
  return false;
}

bool IsCVE202145046Mitigated(std::string log4jVendor, bool foundJNDILookupClass, std::string version) {
  int major = 0, minor = 0, build = 0;
  if (!foundJNDILookupClass) return true;
  if (log4jVendor.compare("log4j-core") != 0) return true;
  if (ParseVersion(version, major, minor, build)) {
    if (major < 2) return true;
    if ((major == 2) && (minor == 12) && (build >= 2)) return true;
    if ((major == 2) && (minor > 15)) return true;
  }
  return false;
}

bool IsCVE202145105Mitigated(std::string log4jVendor, std::string version) {
  int major = 0, minor = 0, build = 0;
  if (log4jVendor.compare("log4j-core") != 0) return true;
  if (ParseVersion(version, major, minor, build)) {
    if (major < 2) return true;
    if ((major == 2) && (minor == 12) && (build >= 3)) return true;
    if ((major == 2) && (minor > 16)) return true;
  }
  return false;
}

int32_t ScanFileArchive(bool console, bool verbose, std::wstring file, std::wstring alternate) {
  int32_t     rv = ERROR_SUCCESS;
  unsigned long bytesWritten = 0;
  unzFile     zf = NULL;
  unz_file_info64 file_info;
  char*       p = NULL;
  char        buf[256];
  char        filename[_MAX_PATH + 1];
  wchar_t     tmpPath[_MAX_PATH + 1];
  wchar_t     tmpFilename[_MAX_PATH + 1];
  bool        foundLog4j = false;
  bool        foundLog4j1x = false;
  bool        foundLog4j2x = false;
  bool        foundJNDILookupClass = false;
  bool        foundManifest = false;
  bool        foundLog4j1xPOM = false;
  bool        foundLog4j2xPOM = false;
  bool        foundLog4j2xCorePOM = false;
  bool        foundManifestVendor = false;
  bool        foundManifestVersion = false;
  bool        foundLog4jManifest = false;
  bool        cve20214104Mitigated = false;
  bool        cve202144228Mitigated = false;
  bool        cve202145046Mitigated = false;
  bool        cve202145105Mitigated = false;
  std::string manifest;
  std::string pomLog4j1x;
  std::string pomLog4j2x;
  std::string pomLog4j2xCore;
  std::string manifestVendor;
  std::string manifestVersion;
  std::string log4jVendor;
  std::string log4jVersion;

  zlib_filefunc64_def zfm = { 0 };
  fill_win32_filefunc64W(&zfm);

  if (!alternate.empty()) {
    zf = unzOpen2_64(alternate.c_str(), &zfm);
  } else {
    zf = unzOpen2_64(file.c_str(), &zfm);
  }
  if (NULL != zf) {
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
          if (0 ==
              stricmp(filename, "org/apache/logging/log4j/core/lookup/JndiLookup.class")) {
            foundJNDILookupClass = true;
          }
          if (0 ==
              stricmp(filename, "META-INF/maven/log4j/log4j/pom.properties")) {
            foundLog4j1xPOM = true;
            UncompressContents(zf, pomLog4j1x);
          }
          p = strstr(filename, "META-INF/maven/org.apache.logging.log4j");
          if (NULL != p) {
            if (0 == stricmp(filename, "META-INF/maven/org.apache.logging.log4j/log4j-core/pom.properties")) {
              foundLog4j2xCorePOM = true;
              UncompressContents(zf, pomLog4j2xCore);
            } else {
              p = strstr(filename, "/pom.properties");
              if (NULL != p) {
                foundLog4j2xPOM = true;
                UncompressContents(zf, pomLog4j2x);
              }
            }
          }
          if (0 == stricmp(filename, "META-INF/MANIFEST.MF")) {
            foundManifest = true;
            UncompressContents(zf, manifest);
          }

          //
          // Add Support for nested archive files
          //
          p = &filename[0] + (strlen(filename) - 4);
          if ((0 == stricmp(p, ".jar")) || (0 == stricmp(p, ".war")) ||
              (0 == stricmp(p, ".ear")) || (0 == stricmp(p, ".zip"))) {
            if (0 == stricmp(p, ".jar")) {
              repSummary.scannedJARs++;
            }
            if (0 == stricmp(p, ".war")) {
              repSummary.scannedWARs++;
            }
            if (0 == stricmp(p, ".ear")) {
              repSummary.scannedEARs++;
            }
            if (0 == stricmp(p, ".zip")) {
              repSummary.scannedZIPs++;
            }

            GetTempPath(_countof(tmpPath), tmpPath);
            GetTempFileName(tmpPath, L"qua", 0, tmpFilename);

            HANDLE h =
                CreateFile(tmpFilename, GENERIC_READ | GENERIC_WRITE, NULL,
                           NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_TEMPORARY, NULL);

            if (h != INVALID_HANDLE_VALUE) {
              rv = unzOpenCurrentFile(zf);
              if (UNZ_OK == rv) {
                do {
                  memset(buf, 0, sizeof(buf));
                  rv = unzReadCurrentFile(zf, buf, sizeof(buf));
                  if (rv < 0 || rv == 0) break;
                  WriteFile(h, buf, rv, &bytesWritten, NULL);
                } while (rv > 0);
                unzCloseCurrentFile(zf);
              }
              CloseHandle(h);

              std::wstring masked_filename = file + L"!" + A2W(filename);
              std::wstring alternate_filename = tmpFilename;

              ScanFileArchive(console, verbose, masked_filename, alternate_filename);

              DeleteFile(alternate_filename.c_str());
            }
          }
        }

        rv = unzGoToNextFile(zf);
      } while (UNZ_OK == rv);
    }

    unzClose(zf);
  }

  // Reset error conditiomn, unzGoToNextFile returns a non-zero error code to break from loop
  //
  rv = ERROR_SUCCESS;

  //
  // If we have detected some evidence of Log4j then lets check to see if we can
  // detect CVE-2021-44228
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
      cve202145046Mitigated = IsCVE202145046Mitigated(log4jVendor, foundJNDILookupClass, log4jVersion);
      cve202145105Mitigated = IsCVE202145105Mitigated(log4jVendor, log4jVersion);
    } else {
      if (foundLog4j1x && (foundLog4j1xPOM || foundLog4jManifest)) {
        cve20214104Mitigated = IsCVE20214104Mitigated(log4jVendor, log4jVersion);
      }
    }

    if (foundLog4j2xCorePOM && (!cve202144228Mitigated || !cve202145046Mitigated|| !cve202145105Mitigated)) {

      repSummary.foundVunerabilities++;
      cveStatus = "Potentially Vulnerable (";
      cveStatus += !cve202144228Mitigated ? " CVE-2021-44228: Found" : " CVE-2021-44228: NOT Found";
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
    } else if (foundJNDILookupClass && foundLog4j2x && cve202144228Mitigated && cve202145046Mitigated && cve202145105Mitigated) {
      cveStatus = "Mitigated";
    } else if (!foundJNDILookupClass && foundLog4j1x) {
      cveStatus = "N/A";
    } else {
      cveStatus = "Unknown";
    }

    repVulns.push_back(CReportVulnerabilities(
        file, A2W(manifestVersion), A2W(manifestVendor), foundLog4j, foundLog4j1x, foundLog4j2x,
        foundJNDILookupClass, foundLog4jManifest, A2W(log4jVersion), A2W(log4jVendor), cve20214104Mitigated, 
        cve202144228Mitigated, cve202145046Mitigated, cve202145105Mitigated, A2W(cveStatus)));

    if (console) {
      wprintf(L"Log4j Found: '%s' ( Manifest Vendor: %S, Manifest Version: %S, JNDI Class: %s, Log4j Vendor: %S, Log4j Version: %S, CVE Status: %S )\n",
              file.c_str(), manifestVendor.c_str(), manifestVersion.c_str(), foundJNDILookupClass ? L"Found" : L"NOT Found", log4jVendor.c_str(),
              log4jVersion.c_str(), cveStatus.c_str());
    }
  }

  return rv;
}

int32_t ScanFile(bool console, bool verbose, std::wstring file) {
  int32_t rv = ERROR_SUCCESS;
  wchar_t drive[_MAX_DRIVE];
  wchar_t dir[_MAX_DIR];
  wchar_t fname[_MAX_FNAME];
  wchar_t ext[_MAX_EXT];

  if (0 == _wsplitpath_s(file.c_str(), drive, dir, fname, ext)) {
    if (0 == _wcsicmp(ext, L".jar")) {
      repSummary.scannedJARs++;
      rv = ScanFileArchive(console, verbose, file, L"");
    }
    if (0 == _wcsicmp(ext, L".war")) {
      repSummary.scannedWARs++;
      rv = ScanFileArchive(console, verbose, file, L"");
    }
    if (0 == _wcsicmp(ext, L".ear")) {
      repSummary.scannedEARs++;
      rv = ScanFileArchive(console, verbose, file, L"");
    }
    if (0 == _wcsicmp(ext, L".zip")) {
      repSummary.scannedZIPs++;
      rv = ScanFileArchive(console, verbose, file, L"");
    }
  } else {
    rv = errno;
  }

  return rv;
}

int32_t ScanDirectory(bool console, bool verbose, std::wstring directory) {
  int32_t rv = ERROR_SUCCESS;
  std::wstring search = directory + std::wstring(L"*.*");
  WIN32_FIND_DATA FindFileData;
  HANDLE hFind;
  wchar_t err[1024] = {0};

  hFind = FindFirstFile(search.c_str(), &FindFileData);
  if (hFind == INVALID_HANDLE_VALUE) {
    rv = GetLastError();
  } else {
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
        repSummary.scannedDirectories++;

        std::wstring dir =
            directory + std::wstring(FindFileData.cFileName) + std::wstring(L"\\");
        rv = ScanDirectory(console, verbose, dir);
        if (ERROR_SUCCESS != rv) {
          if (verbose) {
            wprintf(L"Failed to process directory '%s' (rv: %d)\n", dir.c_str(), rv);
          }
          swprintf_s(err, L"Failed to process directory '%s' (rv: %d)", dir.c_str(), rv);
          error_array.push_back(err);
        }

        // TODO: Look for suspect directory structures containing raw log4j java
        // classes
        //

      } else {
        repSummary.scannedFiles++;

        std::wstring file = directory + std::wstring(FindFileData.cFileName);
        rv = ScanFile(console, verbose, file);
        if (ERROR_SUCCESS != rv) {
          if (verbose) {
            wprintf(L"Failed to process file '%s' (rv: %d)\n", file.c_str(), rv);
          }
          swprintf_s(err, L"Failed to process file '%s' (rv: %d)", file.c_str(), rv);
          error_array.push_back(err);
        }
      }

    } while (FindNextFile(hFind, &FindFileData));
    FindClose(hFind);
  }

  return rv;
}

int32_t ScanLocalDrives(bool console, bool verbose) {
  int32_t rv = ERROR_SUCCESS;
  DWORD rt = 0;
  wchar_t drives[256];

  wcscpy_s(drives, L"");
  rt = GetLogicalDriveStrings(_countof(drives), drives);
  for (uint32_t i = 0; i < rt; i += 4) {
    wchar_t* drive = &drives[i];
    DWORD type = GetDriveType(drive);
    if ((DRIVE_FIXED == type) || (DRIVE_RAMDISK == type)) {
      ScanDirectory(console, verbose, drive);
    }
  }

  return rv;
}

int32_t ScanNetworkDrives(bool console, bool verbose) {
  int32_t rv = ERROR_SUCCESS;
  DWORD rt = 0;
  wchar_t drives[256];

  wcscpy_s(drives, L"");
  rt = GetLogicalDriveStrings(_countof(drives), drives);
  for (uint32_t i = 0; i < rt; i += 4) {
    wchar_t* drive = &drives[i];
    DWORD type = GetDriveType(drive);
    if (DRIVE_REMOTE == type) {
      ScanDirectory(console, verbose, drive);
    }
  }

  return rv;
}

