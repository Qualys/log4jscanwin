// CVE-2021-44228-Scan.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <windows.h>
#include <stdint.h>
#include <iostream>
#include <vector>
#include <string>

#include "zlib/zlib.h"
#include "minizip/unzip.h"


#define ARGX3(s1,s2,s3) (!stricmp(argv[i], s1)||!stricmp(argv[i], s2)||!stricmp(argv[i], s3))
#define ARG(S) ARGX3("-" #S, "--" #S, "/" #S)
#define ARGPARAMCOUNT(X) ((i+X) <= (argc-1))


class CReportSummary {
 public:
  uint64_t scannedFiles;
  uint64_t scannedDirectories;
  uint64_t scannedZIPs;
  uint64_t scannedJARs;
  uint64_t scannedWARs;
  uint64_t scannedEARs;
  uint64_t foundVunerabilities;

  CReportSummary() {
    scannedFiles = 0;
    scannedDirectories = 0;
    scannedZIPs = 0;
    scannedJARs = 0;
    scannedWARs = 0;
    scannedEARs = 0;
    foundVunerabilities = 0;
  }
};

class CReportVunerabilities {
 public:
  std::string file;
  std::string version;
  bool detectedLog4j;
  bool detectedCVE;
};

class CCommandLineOptions {
 public:
  bool scanLocalDrives;
  bool scanNetworkDrives;
  bool scanFile;
  std::string file;
  bool scanDirectory;
  std::string directory;
  bool verbose;
  bool no_logo;
  bool help;

  CCommandLineOptions() {
    scanLocalDrives = false;
    scanNetworkDrives = false;
    scanFile = false;
    file.clear();
    scanDirectory = false;
    directory.clear();
    verbose = false;
    no_logo = false;
    help = false;
  }
};

CCommandLineOptions cmdline_options;
CReportSummary repSummary;
std::vector<CReportVunerabilities> repVulns;


bool VulnerableVersionCheck( std::string version ) {
  int major = atoi( version.c_str() );
  if ( major < 2 ) return false;

  int minor = atoi( version.substr( version.find( ".", 0 ) + 1, version.rfind( ".", version.size() ) ).c_str() );
  if ( minor >= 15 ) return false;

  int revision = atoi( version.substr( version.rfind( ".", version.size() ) + 1, version.size() - ( version.rfind( ".", version.size() ) ) ).c_str() );
  if ( revision >= 2 ) return false;

  return true;
}


int32_t ScanFileArchive( std::string file ) {
  int32_t rv = ERROR_SUCCESS;
  unzFile zf = NULL;
  unz_file_info64 file_info;
  char filename[_MAX_PATH];
  bool foundLog4j = false;
  bool foundJNDILookupClass = false;
  bool foundLog4jManifest = false;
  bool foundVulnerableVersion = false;
  char* p = NULL;
  char buf[2048];
  std::string manifest;
  std::string version = "Unknown";

  zf = unzOpen64( file.c_str() );
  if ( NULL != zf ) {

    //
    // Check to see if there is evidence of Log4j being in the archive
    //
    rv = unzGoToFirstFile( zf );
    if ( UNZ_OK == rv )
    {
      do
      {
        rv = unzGetCurrentFileInfo64( zf, &file_info, filename, _countof(filename), NULL, 0, NULL, 0 );
        if ( UNZ_OK == rv )
        {
          p = strstr( filename, "org/apache/logging/log4j" );
          if ( NULL != p ) {
            foundLog4j = true;
          }
          p = strstr( filename, "org/apache/logging/log4j/core/lookup/JndiLookup.class" );
          if ( NULL != p ) {
            foundJNDILookupClass = true;
          }
        }
        rv = unzGoToNextFile( zf );
      } while ( UNZ_OK == rv );
    }

    //
    // If we have detected some evidence of Log4j then lets check to see if we can detect 
    // CVE-2021-44228
    //
    if ( foundLog4j ) {

      rv = unzLocateFile( zf, "META-INF/MANIFEST.MF", FALSE );
      if ( UNZ_OK == rv ) {
        rv = unzOpenCurrentFile( zf );
        if ( UNZ_OK == rv ) {
          do
          {
            memset( buf, 0, sizeof(buf) );
            rv = unzReadCurrentFile( zf, buf, sizeof(buf) );
            if (rv < 0 || rv == 0) break;
            manifest.append( buf, rv );
          } while (rv > 0);
          unzCloseCurrentFile( zf );
        }

        //
        // Check manifest for confirmation of version number only if Implementation-Vendor-Id is org.apache.logging.log4j
        //
        if ( std::string::npos != manifest.find("Implementation-Vendor-Id: org.apache.logging.log4j", 0) ) {
          foundLog4jManifest = true;

          std::string prop("Implementation-Version:");
          size_t pos = manifest.find(prop.c_str() + 1, 0);
          size_t eol = manifest.find("\r\n", pos);
          version = manifest.substr(pos + prop.size(), eol - (pos + prop.size()));

          if ( VulnerableVersionCheck( version ) ) {
            foundVulnerableVersion = true;
          }
        }
      }
    }
    unzClose( zf );
  }

  if ( !cmdline_options.no_logo ) {
    if ( foundLog4j ) {
      std::string cveStatus;

      if ( foundJNDILookupClass && foundVulnerableVersion ) {
        cveStatus = "Potentially Vulnerable";
      } else if ( !foundJNDILookupClass && foundLog4jManifest ) {
        cveStatus = "Mitigated";
      } else if ( foundJNDILookupClass && foundLog4jManifest && !foundVulnerableVersion ) {
        cveStatus = "Mitigated";
      } else {
        cveStatus = "Unknown";
      }

      printf( "Log4j Found: '%s' ( Version: '%s', JDNI Class: %s, Manifest Owner: %s, CVE Status: %s )\n",
              file.c_str(),
              version.c_str(),
              foundJNDILookupClass ? "Found" : "NOT Found",
              foundLog4jManifest ? "Log4j" : "Unknown (Uber/Shaded Jar?)",
              cveStatus.c_str() );
    }
  }

  return rv;
}


int32_t ScanFile( std::string file ) {
  int32_t rv = ERROR_SUCCESS;
  char drive[_MAX_DRIVE];
  char dir[_MAX_DIR];
  char fname[_MAX_FNAME];
  char ext[_MAX_EXT];

  repSummary.scannedFiles++;

  if ( 0 == _splitpath_s( file.c_str(), drive, dir, fname, ext ) ) {

    if ( 0 == stricmp( ext, ".zip" ) ) {
       repSummary.scannedZIPs++;
       rv = ScanFileArchive(file);
    }
    if ( 0 == stricmp( ext, ".jar" ) ) {
       repSummary.scannedJARs++;
       rv = ScanFileArchive(file);
    }
    if ( 0 == stricmp( ext, ".war" ) ) {
       repSummary.scannedWARs++;
       rv = ScanFileArchive(file);
    }
    if ( 0 == stricmp( ext, ".ear" ) ) {
       repSummary.scannedEARs++;
       rv = ScanFileArchive(file);
    }
  } else {
    rv = errno;
  }

  return rv;
}


int32_t ScanDirectory( std::string directory ) {
  int32_t rv = ERROR_SUCCESS;
  std::string search = directory + std::string("*.*");
  WIN32_FIND_DATA FindFileData;
  HANDLE hFind;

   hFind = FindFirstFile( search.c_str(), &FindFileData );
   if ( hFind == INVALID_HANDLE_VALUE ) 
   {
     rv = GetLastError();
   } 
   else 
   {
     do {

       repSummary.scannedDirectories++;

       std::string filename( FindFileData.cFileName );

       if ( (filename.size() == 1) && (filename == ".") ) continue;
       if ( (filename.size() == 2) && (filename == "..") ) continue;
       if ( (FindFileData.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) == FILE_ATTRIBUTE_REPARSE_POINT ) continue;
       if ( (FindFileData.dwFileAttributes & FILE_ATTRIBUTE_DEVICE) == FILE_ATTRIBUTE_DEVICE ) continue;
       if ( (FindFileData.dwFileAttributes & FILE_ATTRIBUTE_OFFLINE) == FILE_ATTRIBUTE_OFFLINE ) continue;
       if ( (FindFileData.dwFileAttributes & FILE_ATTRIBUTE_TEMPORARY) == FILE_ATTRIBUTE_TEMPORARY ) continue;
       if ( (FindFileData.dwFileAttributes & FILE_ATTRIBUTE_VIRTUAL) == FILE_ATTRIBUTE_VIRTUAL ) continue;

       if ( (FindFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == FILE_ATTRIBUTE_DIRECTORY ) {
         std::string dir = directory + std::string(FindFileData.cFileName) + std::string("\\");
         rv = ScanDirectory( dir );
         if ( ERROR_SUCCESS != rv ) {
           if ( cmdline_options.verbose ) {
             printf( "Failed to process directory '%s' (rv: %d)\n", dir.c_str(), rv );
           }
         }

         // TODO: Look for suspect directory structures containing raw log4j java classes
         //

       } else {
         std::string file = directory + std::string( FindFileData.cFileName );
         rv = ScanFile( file );
         if ( ERROR_SUCCESS != rv ) {
           if ( cmdline_options.verbose ) {
             printf( "Failed to process file '%s' (rv: %d)\n", file.c_str(), rv );
           }
         }
       }

     } while ( FindNextFile(hFind, &FindFileData) );
     FindClose( hFind );
   }

  return rv;
}


int32_t ScanLocalDrives() {
  int32_t rv = ERROR_SUCCESS;
  DWORD rt = 0;
  char drives[256];

  strcpy_s( drives, "" );
  rt = GetLogicalDriveStrings( _countof(drives), drives );
  for ( uint32_t i = 0; i < rt; i += 4 ) {
    char* drive = &drives[i];
    DWORD type = GetDriveType( drive );
    if ( (DRIVE_FIXED == type) || (DRIVE_RAMDISK == type) ) {
      ScanDirectory( drive );
    }
  }

  return rv;
}


int32_t ScanNetworkDrives() {
  int32_t rv = ERROR_SUCCESS;
  DWORD rt = 0;
  char drives[256];

  strcpy_s( drives, "" );
  rt = GetLogicalDriveStrings( _countof(drives), drives );
  for ( uint32_t i = 0; i < rt; i += 4 ) {
    char* drive = &drives[i];
    DWORD type = GetDriveType( drive );
    if ( DRIVE_REMOTE == type ) {
      ScanDirectory( drive );
    }
  }

  return rv;
}


int32_t PrintHelp( _In_ int32_t argc, _In_ char* argv[] ) {
  int32_t rv = ERROR_SUCCESS;

  printf("/scan\n");
  printf("  Scan local drives for vunerable JAR, WAR, EAR, ZIP files used by various Java applications.\n");
  printf("/scan_network\n");
  printf("  Scan network drives for vunerable JAR, WAR, EAR, ZIP files used by various Java applications.\n");
  printf("/scan_directory \"C:\\Some\\Path\"\n");
  printf("  Scan a specific directory for vunerable JAR, WAR, EAR, ZIP files used by various Java applications.\n");
  printf("/scan_file \"C:\\Some\\Path\\Some.jar\"\n");
  printf("  Scan a specific file for CVE-2021-44228.\n");
  printf("\n");

  return rv;
}


int32_t ProcessCommandLineOptions( _In_ int32_t argc, _In_ char* argv[] ) {
  int32_t rv = ERROR_SUCCESS;

  for ( int32_t i=1; i<argc; i++ ) {
    if ( 0 ) {
    } else if ( ARG(scan) ) {
      cmdline_options.scanLocalDrives = true;
    } else if ( ARG(scan_network) ) {
      cmdline_options.scanNetworkDrives = true;
    } else if ( ARG(scan_file) && ARGPARAMCOUNT(1) ) {
      cmdline_options.scanFile = true;
      cmdline_options.file = argv[i+1];
    } else if ( ARG(scan_directory) && ARGPARAMCOUNT(1) ) {
      cmdline_options.scanDirectory = true;
      cmdline_options.directory = argv[i+1];
    } else if ( ARG(nologo) ) {
      cmdline_options.no_logo = true;
    } else if ( ARG(v) || ARG(verbose) ) {
      cmdline_options.verbose = true;
    } else if ( ARG(h) || ARG(help) ) {
      cmdline_options.help = true;
    }
  }

  return rv;
}


int32_t __cdecl main( _In_ int32_t argc, _In_ char* argv[] )
{
  int32_t rv = ERROR_SUCCESS;

  rv = ProcessCommandLineOptions( argc, argv );
  if ( ERROR_SUCCESS != rv ) {
    printf("Failed to process command line pptions.\n");
    goto END;
  }

  if ( !cmdline_options.no_logo ) {
    printf("Qualys CVE-2021-44228 Log4j Vulnerability Scanner 1.0\n");
    printf("https://www.qualys.com/\n\n");
  }

  if ( cmdline_options.help ) {
    PrintHelp(argc, argv);
    goto END;
  }

  if ( cmdline_options.scanLocalDrives ) {
    if ( !cmdline_options.no_logo ) {
      printf( "Scanning Local Drives...\n" );
    }
    ScanLocalDrives();
  }

  if ( cmdline_options.scanNetworkDrives ) {
    if ( !cmdline_options.no_logo ) {
      printf( "Scanning Network Drives...\n" );
    }
    ScanNetworkDrives();
  }

  if ( cmdline_options.scanDirectory ) {
    if ( !cmdline_options.no_logo ) {
      printf( "Scanning '%s'...\n", cmdline_options.directory.c_str() );
    }
    ScanDirectory(cmdline_options.directory);
  }

  if ( cmdline_options.scanFile ) {
    if ( !cmdline_options.no_logo ) {
      printf( "Scanning '%s'...\n", cmdline_options.file.c_str() );
    }
    ScanFile(cmdline_options.file);
  }


END:
  return rv;
}

