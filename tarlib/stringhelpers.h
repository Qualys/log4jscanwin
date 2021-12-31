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

namespace tarlib
{
   namespace utils
   {
      struct ci_char_traits : public std::char_traits<char> 
      {
	      static bool eq(char c1, char c2) { return toupper(c1) == toupper(c2); }
	      static bool ne(char c1, char c2) { return toupper(c1) != toupper(c2); }
	      static bool lt(char c1, char c2) { return toupper(c1) <  toupper(c2); }
	      static int compare(const char* s1, const char* s2, size_t n) {
		      while( n-- != 0 ) {
			      if( toupper(*s1) < toupper(*s2) ) return -1;
			      if( toupper(*s1) > toupper(*s2) ) return 1;
			      ++s1; ++s2;
		      }
		      return 0;
	      }
	      static const char* find(const char* s, int n, char a) {
		      while( n-- > 0 && toupper(*s) != toupper(a) ) {
			      ++s;
		      }
		      return s;
	      }
      };

      typedef std::basic_string<char, ci_char_traits> ci_string;

      bool ends_with_ci(std::string const& text, std::string const& ending);
      bool starts_with_ci(std::string const& text, std::string const& ending);
   }
}