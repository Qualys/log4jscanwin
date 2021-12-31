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

#include "stringhelpers.h"

namespace tarlib
{
   namespace utils
   {
      bool ends_with_ci(std::string const& text, std::string const& ending)
      {
	      ci_string citext = text.c_str();
	      ci_string ciending = ending.c_str();

	      if (citext.length() >= ciending.length()) {
		      return (0 == citext.compare (citext.length() - ciending.length(), ciending.length(), ciending));
	      }

	      return false;
      }

      bool starts_with_ci(std::string const& text, std::string const& ending)
      {
	      ci_string citext = text.c_str();
	      ci_string ciending = ending.c_str();

	      if (citext.length() >= ciending.length()) {
		      return (0 == citext.compare (0, ciending.length(), ciending));
	      }

	      return false;
      }

   }
}