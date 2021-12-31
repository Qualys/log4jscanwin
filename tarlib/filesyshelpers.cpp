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

#include "filesyshelpers.h"
#include "stringhelpers.h"

#include <Shlobj.h>
#pragma comment(lib, "Shell32")

#include <Shlwapi.h>
#pragma comment(lib, "Shlwapi")

namespace tarlib
{
   namespace utils
   {
      bool createfolder(std::string const &folder)
      {
         // TODO: only available for WinXP and higher
         int ret = ::SHCreateDirectoryExA(NULL, folder.c_str(), NULL);
         return ERROR_SUCCESS == ret;
      }

      std::string path_combine(std::string const& path1, std::string const &path2)
      {
         // TODO: only available for WinXP and higher
         std::string result;
         result.resize(MAX_PATH);
         ::PathCombineA(&result[0], path1.c_str(), path2.c_str());

         return result;
      }

      bool path_exists(std::string const &path)
      {
         DWORD attr = GetFileAttributesA(path.c_str());
         return attr != INVALID_FILE_ATTRIBUTES;
      }

      bool path_is_folder(std::string const &path)
      {
         DWORD attr = GetFileAttributesA(path.c_str());
         return (attr != INVALID_FILE_ATTRIBUTES) && 
            ((attr & FILE_ATTRIBUTE_DIRECTORY) == FILE_ATTRIBUTE_DIRECTORY);
      }

      bool path_is_file(std::string const &path)
      {
         DWORD attr = GetFileAttributesA(path.c_str());
         return (attr != INVALID_FILE_ATTRIBUTES) && 
                (((attr & FILE_ATTRIBUTE_NORMAL) == FILE_ATTRIBUTE_NORMAL) ||
                 ((attr & FILE_ATTRIBUTE_ARCHIVE) == FILE_ATTRIBUTE_ARCHIVE));
      }

      std::string extract_filename(std::string const &path)
      {
         size_t pos = path.find_last_of("/\\");
         if(std::string::npos == pos)
            return path;

         return path.substr(pos+1);
      }

      std::string extract_foldername(std::string const &path)
      {
         size_t pos = path.find_last_of("/\\");
         if(std::string::npos == pos)
            return path;

         return path.substr(0, pos+1);
      }
   }
}