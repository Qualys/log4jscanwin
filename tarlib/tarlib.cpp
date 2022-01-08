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

#include "tarlib.h"

#include "filesyshelpers.h"
#include "stringhelpers.h"

namespace tarlib
{
   namespace utils
   {
      inline unsigned char octal_to_numeric(char octal)
      {
         return (octal >= '0' && octal <= '7') ? octal - '0' : 0;
      }

      long long octal8_to_numeric(const char octal[8])
      {
         long long result = 0;

         int pos = 0;
         while(octal[pos]==' ' || octal[pos] == '0') ++pos;

         for(int i = pos; i < 8 && octal[i] != 0 && octal[i] != ' '; ++i)
         {
            result = result * 8 + octal_to_numeric(octal[i]);
         }

         return result;
      }

      long long octal12_to_numeric(const char octal[12])
      {
         long long result = 0;

         int pos = 0;
         while(octal[pos]==' ' || octal[pos] == '0') ++pos;

         for(int i = pos; i < 12 && octal[i] != 0 && octal[i] != ' '; ++i)
         {
            result = result * 8 + octal_to_numeric(octal[i]);
         }

         return result;
      }

      std::string numeric_to_octal(long long number, unsigned char length)
      {
         if(length == 0)
            return "";

         char buffer[32] = {0};
         _i64toa_s(number, buffer, 32, 8);
         int reslen = strlen(buffer);

         char* result = new char[length];
         memset(result, '0', length);

         strncpy_s(result + length - reslen, length, buffer, reslen);
         
         std::string snum(result, length);

         return snum;
      }
   }

   using namespace std;
   using namespace tarlib::utils;

   tarHeader::tarHeader():
      ownerid(0),
      groupid(0),
      filesize(0),
      unixtime(0),
      checksum(0),
      indicator(0),
      devicemajor(0),
      deviceminor(0),
      tarType(tarFormatV7)
   {
      memset(filemode, 0 , sizeof(filemode));
      memset(version, 0, sizeof(version));
   }

   unsigned long long tarHeader::get_checksum(const tarHeaderAscii& asciiHeader)
   {
      long long crc = 0;
      for(int i = 0; i < 148; ++i)
         crc += asciiHeader.row[i];
      for(int i = 0; i < 8; ++i)
         crc += ' ';
      for(int i = 156; i < 500; ++i)
         crc += asciiHeader.row[i];
      return crc;
   }

   tarHeader tarHeader::fromAscii(const tarHeaderAscii& asciiHeader)
   {
      tarHeader header;

      long long crc = get_checksum(asciiHeader);
      long long originalcrc = octal8_to_numeric(asciiHeader.header.checksum);

      if((crc == originalcrc) || 
         // there seem to be some tar files without checksums
         (originalcrc == 0 && strlen(asciiHeader.header.filename) > 0))
      {
         header.filename = asciiHeader.header.filename;
         memcpy(header.filemode, asciiHeader.header.filemode, 8);
         header.ownerid = octal8_to_numeric(asciiHeader.header.ownerid);
         header.groupid = octal12_to_numeric(asciiHeader.header.groupid);
         header.filesize = octal12_to_numeric(asciiHeader.header.filesize);
         header.unixtime = octal12_to_numeric(asciiHeader.header.lasttime);
         header.indicator = asciiHeader.header.typeindicator;
         header.checksum = originalcrc;
         header.linkedfilename = asciiHeader.header.linkedfilename;

         if(memcmp(&asciiHeader.header.magicwithversion[0], OLDGNU_MAGIC, 8) == 0)
         {
            header.tarType = tarFormatOldGNU;
         }
         else if(memcmp(&asciiHeader.header.magicwithversion[0], GNU_MAGIC, 8) == 0)
         {
            header.tarType = tarFormatGNU;
         }
         else if(memcmp(&asciiHeader.header.magicwithversion[0], USTAR_MAGIC, 8) == 0)
         {
            header.tarType = tarFormatUSTAR;
         }

         if(header.tarType != tarFormatV7)
         {
            header.magic = std::string(&asciiHeader.header.magicwithversion[0], &asciiHeader.header.magicwithversion[5]);
            memcpy(&header.version[0], &asciiHeader.header.magicwithversion[5], 2);
            header.ownername = asciiHeader.header.ownername;
            header.ownergroup = asciiHeader.header.ownergroup;
            header.devicemajor = octal8_to_numeric(asciiHeader.header.devicemajor);
            header.deviceminor = octal8_to_numeric(asciiHeader.header.deviceminor);
            header.filenameprefix = asciiHeader.header.filenameprefix;
         }
      }

      return header;
   }

   // -------------- tarFile ---------------------
   tarFile::tarFile()
   {

   }

   tarFile::tarFile(std::string const &filename, tarFileMode mode, tarFormatType type)
   {
      open(filename, mode, type);
   }

   tarFile::~tarFile()
   {
      close();
   }

   bool tarFile::open(std::string const &filename, tarFileMode mode, tarFormatType type)
   {
      if(_tarfile.is_open())
         return false;

      _filemode = mode;
      _outtype = type;
      _filename = filename;	

      std::ios_base::openmode openmode;
      switch(mode)
      {
      case tarModeRead:
         openmode = std::ios_base::in | std::ios_base::binary;
         break;
      case tarModeWrite:
         openmode = std::ios_base::out | std::ios_base::binary;
         break;
      case tarModeAppend:
         openmode = std::ios_base::out | std::ios_base::app | std::ios_base::binary;
         break;
      }


      _tarfile.open(filename.c_str(), openmode);

      return _tarfile.is_open();
   }

   bool tarFile::extract(std::string const &folder)
   {
      if(_tarfile.is_open() && _filemode != tarModeWrite)
      {
         _tarfile.seekg(std::ios_base::beg);

         bool istar = ends_with_ci(_filename, ".tar");
         bool istarmd5 = ends_with_ci(_filename, ".tar.md5");

         if(!istar && !istarmd5)
            return false;

         createfolder(folder);

         long long total = 0;
         _tarfile.seekg (0, ios::end);
         long long tarsize = _tarfile.tellg();
         _tarfile.seekg (0, ios::beg);

         char block[tarChunkSize] = {0};
         int emptyRecord = 0;
         char zerorecord[tarChunkSize] = {0};
         char bigblock[tarChunkSize * 16] = {0};

         do 
         {
            _tarfile.read(&block[0], tarChunkSize);
            total += tarChunkSize;

            if(memcmp(block, zerorecord, tarChunkSize) == 0)
            {
               emptyRecord++;

               if(tarsize - total < tarChunkSize)
                  break;

               continue;
            }

            tarHeaderAscii headerAscii;
            memcpy(&headerAscii.row[0], block, sizeof(headerAscii));

            tarHeader header = tarHeader::fromAscii(headerAscii);

            switch(header.indicator)
            {
            case '0': case 0:
               {
                  if(header.filesize > 0)
                  {
                     // open the file and copy the content
                     ofstream file;
                     file.open((folder + header.filename).c_str(), ios::binary);
                     if(file.is_open())
                     {
                        long long filetotal = 0;

                        do 
                        {
                           size_t toread = (header.filesize - filetotal) > sizeof(bigblock) ? sizeof(bigblock) : (size_t)(header.filesize - filetotal);
                           if((toread % tarChunkSize) != 0)
                              toread = (1 + (toread / tarChunkSize)) * tarChunkSize;
                           size_t left = (header.filesize - filetotal) > toread ? toread : (size_t)(header.filesize - filetotal);

                           _tarfile.read(&bigblock[0], toread);
                           size_t byteread = _tarfile.gcount();
                           total += byteread;
                           filetotal += byteread;

                           file.write(&bigblock[0], left);

                        }while(total < tarsize && filetotal < header.filesize);

                        file.close();
                     }
                     else
                     {
                        // if file cannot be opened then position the cursor to the next tar entry header
                        _tarfile.seekg((streamoff)header.filesize, ios_base::cur);
                     }
                  }
               }
               break;
            case '5': // directory
               {
                  createfolder(folder + header.filename);
               }
               break;
            }

         } while(total < tarsize);

         if(istarmd5 && tarsize > total + 33)
         {
            char md5hash[32];
            _tarfile.read(&md5hash[0], 32);

            total += 32;
            size_t left = (size_t)(tarsize - total);
            _tarfile.read(&block[0], left);

            if(block[0] == ' ' && block[1] == ' ' && block[left-1] == 0x0a)
            {
               std::string tarname = std::string(&block[2], &block[left]);
            }
         }

         _tarfile.close();

         return true;
      }

      return false;
   }

   void tarFile::close()
   {
      if(_tarfile.is_open())
         _tarfile.close();

      _filename.clear();
   }

   tarEntry tarFile::get_first_entry()
   {
      if(!_tarfile.is_open())
         return tarEntry::makeEmpty();

      _tarfile.seekg (0, ios::end);
      _filesize = _tarfile.tellg();
      _nextentrypos = (streampos)0;
      _headersize = 0;

      return get_next_entry();
   }

   tarEntry tarFile::get_next_entry()
   {
      if(!_tarfile.is_open())
         return tarEntry::makeEmpty();

      char block[tarChunkSize] = {0};
      char zerorecord[tarChunkSize] = {0};

      _tarfile.seekg(_nextentrypos);

      _tarfile.read(&block[0], tarChunkSize);
      long long bytesRead = _tarfile.gcount();
      _headersize += bytesRead;
      _nextentrypos += (streamoff)bytesRead;

      // if we don't have 2 chunks, we don't have a valid tar file
      if(bytesRead < tarChunkSize*2)
      {
         return tarEntry();
      }

      if(memcmp(block, zerorecord, tarChunkSize) == 0)
      {
         if(_filesize - _headersize < tarChunkSize)
         {
            // TODO: read checksum
         }

         return tarEntry();
      }

      tarHeaderAscii headerAscii;
      memcpy(&headerAscii.row[0], block, sizeof(headerAscii));

      tarHeader header = tarHeader::fromAscii(headerAscii);

      if(header.filesize > 0)
      {
         if(header.filesize % tarChunkSize == 0)
            _nextentrypos += (std::streamoff)header.filesize;
         else
            _nextentrypos += (std::streamoff)(tarChunkSize * (1 + header.filesize/tarChunkSize));
      }

      return tarEntry(&_tarfile, _filemode, _tarfile.tellg(), header);
   }

   void tarFile::rewind()
   {
      if(_tarfile.is_open())
         _tarfile.seekg(std::ios::beg);
   }

   // ----------------- tarFile ------------------
   tarEntry::tarEntry():
      _empty(true),
      _filestream(NULL),
      _totalread(0),
      _lastread(0),
      _filemode(tarModeRead)
   {
   }

   tarEntry::tarEntry(tarMD5 const & md5, tarFileMode filemode):
      _empty(true),
      _filestream(NULL),
      _totalread(0),
      _lastread(0),
      _filemode(filemode)
   {
      this->md5 = md5;
   }

   tarEntry::tarEntry(std::fstream* tarfile, tarFileMode filemode, std::streampos pos, tarHeader& header):
      _filestream(tarfile), 
      _filemode(filemode),
      _entrypos(pos), 
      _empty(tarfile == NULL), 
      header(header), 
      _totalread(0), 
      _lastread(0)      
   {

   }


   tarEntry::tarEntry(tarEntry const & cpy)
   {
      this->_filestream = cpy._filestream;
      this->_entrypos = cpy._entrypos;
      this->_empty = cpy._empty;
      this->_totalread = cpy._totalread;
      this->header = cpy.header;
      this->_lastread = cpy._lastread;
      this->_filemode = cpy._filemode;
   }

   tarEntry& tarEntry::operator=(tarEntry const & rhv)
   {
      if(&rhv != this)
      {
         this->_filestream = rhv._filestream;
         this->_entrypos = rhv._entrypos;
         this->_empty = rhv._empty;
         this->_totalread = rhv._totalread;
         this->header = rhv.header;
         this->_lastread = rhv._lastread;
         this->_filemode = rhv._filemode;
      }

      return *this;
   }

   void tarEntry::rewind()
   {
      if(_filestream != NULL && _filestream->is_open())
      {
         if(_filestream->tellg() != _entrypos)
            _filestream->seekg(_entrypos);
      }

      _totalread = 0;
   }

   size_t tarEntry::read(char* buffer, size_t chunksize)
   {
      if(_filemode == tarModeWrite)
         return 0;

      if(_filestream == NULL || buffer == NULL || chunksize == 0)
         return 0;

      long long left = header.filesize - _totalread;
      if(left == 0)
         return 0;

      if(left < chunksize)
         chunksize = (size_t)left;

      _filestream->read(buffer, chunksize);
      _lastread =  _filestream->gcount(); 

      _totalread += _lastread;

      return (size_t)_lastread;
   }

   bool tarEntry::extract(std::string const &folder)
   {
      if(_filemode == tarModeWrite)
         return false;

      switch(header.indicator)
      {
      case tarEntryNormalFile:
      case tarEntryNormalFileNull:
         return extractfile_to_folder(folder);
         break;

      case tarEntryDirectory:
         return createfolder(path_combine(folder, header.filename));
         break;
      }

      return false;
   }

   bool tarEntry::extractfile_to_folder(std::string const &folder)
   {
      if(_filemode == tarModeWrite)
         return false;

      // if the entry is not a normal file this function fails
      if(header.indicator != tarEntryNormalFile && header.indicator != tarEntryNormalFileNull)
         return false;

      // create the output stream
      ofstream outfile(path_combine(folder, header.filename).c_str(), ios::binary);
      // extract to the stream
      return extractfile_to_stream(outfile);
   }

   bool tarEntry::extractfile_to_file(std::string const &filename)
   {
      if(_filemode == tarModeWrite)
         return false;

      // if the entry is not a normal file this function fails
      if(header.indicator != tarEntryNormalFile && header.indicator != tarEntryNormalFileNull)
         return false;

      // create the output stream
      ofstream outfile(filename.c_str(), ios::binary);
      // extract to the stream
      return extractfile_to_stream(outfile);
   }

   bool tarEntry::extractfile_to_stream(std::ofstream &stream)
   {
      if(_filemode == tarModeWrite)
         return false;

      if(stream.is_open() &&
         (header.indicator == tarEntryNormalFile || header.indicator == tarEntryNormalFileNull))
      {
         // create an output buffer
         char chunk[tarChunkSize];
         size_t readsize = 0;
         // read chunks from the tar entry until the end
         while((readsize = read(chunk)) > 0)
         {
            // write the chunk to the output file
            stream.write(chunk, readsize);
         }

         return true;
      }

      return false;
   }

   tarEntry tarEntry::makeEmpty()
   {
      return tarEntry();
   }

   tarEntry tarEntry::makeMD5(char* buffer, size_t size)
   {
      if(buffer != NULL && size > 0)
      {
         char* start = buffer;
         char* end = start;
         while(*end++ != 0);

         tarMD5 md5;
         md5.hash = std::string(start, end);
         md5.tarname = std::string(end+1, start + size);

         return tarEntry(md5);
      }

      return tarEntry::makeEmpty();
   }
}
