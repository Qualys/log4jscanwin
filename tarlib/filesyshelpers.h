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

#include <windows.h>
#include <string>

namespace tarlib
{
   namespace utils
   {
      bool createfolder(std::string const &folder);
      std::string path_combine(std::string const& path1, std::string const &path2);
      bool path_exists(std::string const &path);
      bool path_is_folder(std::string const &path);
      bool path_is_file(std::string const &path);
      std::string extract_filename(std::string const &path);
      std::string extract_foldername(std::string const &path);
   }
}
