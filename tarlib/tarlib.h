// +-------------------------------------------------------------------------------------------+
// | tarlib - Windows library for handling TAR files                                           |
// | Created by Marius Bancila                                                                 |
// | Version 1.1 (2012.09.14)                                                                  |
// | Discussion board: http://codexpert.ro/forum/viewforum.php?f=47                            |
// | License: Creative Commons Attribution-ShareAlike (CC BY-SA)                               |
// |          http://creativecommons.org/licenses/by-sa/3.0/                                   |
// | Disclaimer: The software is provided "as-is".                                             |
// |             No claim of suitability, guarantee, or any warranty whatsoever is provided.   |
// +-------------------------------------------------------------------------------------------+

#pragma once

#include <string>
#include <fstream>

#define OLDGNU_MAGIC	   "ustar  "
#define USTAR_MAGIC		"ustar\000"
#define GNU_MAGIC       "GNUtar " 

#define TSUID    04000		// set UID on execution
#define TSGID    02000		// set GID on execution
#define TSVTX    01000		// reserved
#define TUREAD   00400		// read by owner
#define TUWRITE  00200		// write by owner
#define TUEXEC   00100		// execute/search by owner
#define TGREAD   00040		// read by group
#define TGWRITE  00020		// write by group
#define TGEXEC   00010		// execute/search by group
#define TOREAD   00004		// read by other
#define TOWRITE  00002		// write by other
#define TOEXEC   00001		// execute/search by other

namespace tarlib
{
   enum tarConstants
   {
      tarChunkSize = 512
   };

   enum tarFileMode
   {
      tarModeRead,
      tarModeWrite,
      tarModeAppend
   };

   enum tarFormatType 
   {
      tarFormatV7,
      tarFormatOldGNU,
      tarFormatGNU,
      tarFormatUSTAR,
      tarFormatPOSIX
   };

   enum tarEntryType
   {
      tarEntryNormalFile = '0',
      tarEntryNormalFileNull = 0,
      tarEntryHardLink = '1',
      tarEntrySymlink = '2',
      tarEntryCharSpecial = '3',
      tarEntryBlockSpecial = '4',
      tarEntryDirectory = '5',
      tarEntryFIFO = '6',
      tarEntryContiguousFile = '7',
      tarEntryGlobalExtender = 'g',
      tarEntryExtHeader = 'x',
      tarEntryVendorSpecA = 'A',
      tarEntryVendorSpecB = 'B',
      tarEntryVendorSpecC = 'C',
      tarEntryVendorSpecD = 'D',
      tarEntryVendorSpecE = 'E',
      tarEntryVendorSpecF = 'F',
      tarEntryVendorSpecG = 'G',
      tarEntryVendorSpecH = 'H',
      tarEntryVendorSpecI = 'I',
      tarEntryVendorSpecJ = 'J',
      tarEntryVendorSpecK = 'K',
      tarEntryVendorSpecL = 'L',
      tarEntryVendorSpecM = 'M',
      tarEntryVendorSpecN = 'N',
      tarEntryVendorSpecO = 'O',
      tarEntryVendorSpecP = 'P',
      tarEntryVendorSpecQ = 'Q',
      tarEntryVendorSpecR = 'R',
      tarEntryVendorSpecS = 'S',
      tarEntryVendorSpecT = 'T',
      tarEntryVendorSpecV = 'U',
      tarEntryVendorSpecU = 'V',
      tarEntryVendorSpecX = 'X',
      tarEntryVendorSpecY = 'Y',
      tarEntryVendorSpecZ = 'Z',
   };

   class tarFile;

   /*
   -------+------+------------------------------------------------------
   Offset | Size | Field
   -------+------+------------------------------------------------------
     0   	100	   File name
   100	   8	      File mode
   108	   8	      Owner's numeric user ID
   116	   8	      Group's numeric user ID
   124	   12	      File size in bytes
   136	   12	      Last modification time in numeric Unix time format
   148	   8	      Checksum for header block
   156	   1	      Link indicator (file type)
   157	   100	   Name of linked file

   257	   6	      UStar indicator "ustar"
   263	   2	      UStar version "00"
   265	   32	      Owner user name
   297	   32	      Owner group name
   329	   8	      Device major number
   337	   8	      Device minor number
   345	   155	   Filename prefix
   -------+------+------------------------------------------------------
   */

   // this union represent the header of a tar entry
   // it is a chunk of 512 bytes with all data encoded in ASCII
   // and all numbers in base 8
   union tarHeaderAscii
   {
      char row[tarChunkSize];
      struct 
      {
         char filename[100];           // File name
         char filemode[8];             // File mode
         char ownerid[8];              // Owner's numeric user ID
         char groupid[8];              // Group's numeric user ID
         char filesize[12];            // File size in bytes
         char lasttime[12];            // Last modification time in numeric Unix time format
         char checksum[8];             // Checksum for header block
         char typeindicator;           // Link indicator (file type)
         char linkedfilename[100];     // Name of linked file

         // ignored if the chars at 257 are not "ustar"
         char magicwithversion[8];     // UStar indicator and version
         char ownername[32];           // Owner user name
         char ownergroup[32];          // Owner group name
         char devicemajor[8];          // Device major number
         char deviceminor[8];          // Device minor number
         char filenameprefix[155];     // Filename prefix
         char padding[12];             // padding for end of 512 bytes chunk
      } header;
   };

   // this represents a transformed header for a TAR entry
   struct tarHeader
   {
      std::string filename;
      char filemode[8];
      long long ownerid;
      long long groupid;
      long long filesize;
      long long unixtime;
      unsigned long long checksum;
      char indicator;
      std::string linkedfilename;

      // ignored if the chars at 257 are not "ustar"
      std::string magic;
      char version[2];
      std::string ownername;
      std::string ownergroup;
      long long devicemajor;
      long long deviceminor;
      std::string filenameprefix;

      // helper members
      tarFormatType tarType;

      static tarHeader fromAscii(const tarHeaderAscii& asciiHeader);
      static unsigned long long get_checksum(const tarHeaderAscii& asciiHeader);

      tarHeader();
   };

   // this structure represent an entry in the TAR file that contains an MD5 hash and the name of the archive
   struct tarMD5
   {
      std::string hash;
      std::string tarname;

      bool is_null() const {return hash.empty() && hash.empty();}
   };

   // this is an entry in the TAR file
   // it contains the header for the entry and methods to process the entry
   class tarEntry
   {
      bool _empty;
      tarFileMode _filemode;
      std::fstream* _filestream;
      std::streampos _entrypos;
      long long _totalread;
      long long _lastread;

      // constructors
      tarEntry(std::fstream* tarfile, tarFileMode filemode, std::streampos pos, tarHeader& header);

      // tarFile must be friend to be able to construct an entry from a stream
      friend class tarFile;

   public:
      // these constructors create entries used for extracting
      tarEntry();
      tarEntry(tarMD5 const & md5, tarFileMode filemode = tarModeRead);
      tarEntry(tarEntry const & cpy);
      tarEntry& operator=(tarEntry const & rhv);

      // the entry header
      tarHeader header;

      // md5 entry
      tarMD5 md5;

      // public interface
      bool is_empty() const {return _empty;}
      bool is_md5() const {return !md5.is_null(); }
      long long size_left() const {return header.filesize - _totalread;}

      size_t read(char* buffer, size_t chunksize = tarChunkSize);
      void rewind();

      bool extract(std::string const &folder);
      bool extractfile_to_folder(std::string const &folder);
      bool extractfile_to_file(std::string const &filename);
      bool extractfile_to_stream(std::ofstream &stream);

      // static methods
      static tarEntry makeEmpty();
      static tarEntry makeMD5(char* buffer, size_t size);
   };

   // this is the representation of a tar file
   class tarFile
   {
      std::string _filename;           // name of the archive file
      std::fstream _tarfile;           // stream with the archive
      tarFormatType _outtype;          // type of the archive; only used when writing archives
      tarFileMode _filemode;           // the mode the archive is opened
      std::streampos _nextentrypos;    // position in the stream of the next entry
      long long _filesize;             // total size of the archive stream
      long long _headersize;           // size of bytes of the current read header

      void close();

      tarFile(const tarFile& cpy);
      tarFile& operator=(const tarFile& rhv);
   public:
      tarFile();
      tarFile(std::string const &filename, tarFileMode mode, tarFormatType type = tarFormatUSTAR);
      ~tarFile();

      bool open(std::string const &filename, tarFileMode mode, tarFormatType type = tarFormatUSTAR);
      bool is_open() const {return _tarfile.is_open();}

      bool extract(std::string const &folder);
      tarEntry get_first_entry();
      tarEntry get_next_entry();
      void rewind();
   };
}
