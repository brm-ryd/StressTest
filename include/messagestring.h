#ifndef _DYNAMIC_STRING_H_
#define _DYNAMIC_STRING_H_

#include <string>
#include <stdlib.h>
#include <errno.h>

#ifdef HAVE_CONFIG_H
   #include "config.h"
#endif

#ifdef UNICODE
#define string wstring
#endif

using namespace std;

#include "exceptions.h"

#ifdef LONG_DECIMAL_NUMBERS
typedef unsigned long long decimal_number_type;
#define DECIMAL_NUMBER_FORMAT "%llu"
#else
typedef unsigned int decimal_number_type;
#define DECIMAL_NUMBER_FORMAT "%u"
#endif

#define STRING_NOT_FOUND 0xFFFFFFFF

#ifndef WIN32
#ifndef strCaseCompare
#define strCaseCompare(x, y) strcasecmp(x,y)
#endif

#define TCHAR char
#endif

class MessageString : public string {

 public:

	 static bool caseSensitive;	// default = true

	 #ifdef WIN32
   /** false: case sensitively will be work only for ASCII symbols,
       true: for symbols from user language, comparing will become slower (Windows only),
       default = true
    */
	 static bool caseSensitiveForUseLocale;
	 #endif

 protected:

	void generic_init();

 public:

	MessageString() { generic_init(); }
	MessageString(const TCHAR* init_str);
	MessageString(const MessageString& sourceString);

   ~MessageString();

	inline const TCHAR* operator!(void) const {
		return (*this).c_str();
	}

	inline UInt len() {
		return (UInt)size();
	}

	/** ASSIGNMENT OPERATORS */

	inline const MessageString& operator=(const string& sourceString) {
		(*(string*)this) = sourceString;
		return *this;
	}

	inline const MessageString& operator=(const TCHAR* sourceString) {
		(*(string*)this) = sourceString;
		return *this;
	}

	// COMPARISON OPERATORS

	/** the comparison may be case sensitive or not depending on flag 'caseSensitive' */

	inline bool operator==(const TCHAR* str) const {

      if (caseSensitive)
         return (compare(str) == 0);
      else
   #ifndef WIN32
         return (strCaseCompare(str, c_str()) == 0);
   #else
         if (!caseSensitiveForUseLocale) return (_tcsicmp(str, c_str()) == 0);
         return (CompareString(LOCALE_USER_DEFAULT, NORM_IGNORECASE, str, -1, c_str(), (int)size()) == CSTR_EQUAL);
   #endif
   }

   inline bool operator==(const MessageString& str) const {

      return (*this == (string&)str);
   }

   inline bool operator==(const string& str) const {

      if (caseSensitive)
         return (bool)(!(*this).compare(str));
      else
   #ifndef WIN32
         return (strCaseCompare(str.c_str(), c_str()) == 0);
   #else
         if (!caseSensitiveForUseLocale) return (_tcsicmp(str.c_str(), c_str()) == 0);
         return (CompareString(LOCALE_USER_DEFAULT, NORM_IGNORECASE, str.c_str(), (int)str.size(), c_str(), (int)size()) == CSTR_EQUAL);
   #endif
   }
	inline bool operator!=(const TCHAR* str) const {	return !(*this == str);	}
	inline bool operator!=(const MessageString& str) const {	return !(*this == str);	}

	/** ADDITIONAL METHODS */

	void makeUpper();

	/**
	 returns the number which the currently stored string represents,
	 throws the Exception while overflow or incorrect format
	*/
	double getNumber(
		bool onlyInteger = false, // true - throws the Exception if this condition isn't met
		bool onlyPositive = false // true - throws the Exception if this condition isn't met (onlyPositive means >= 0)
		) const;

   void assignNumber(int n);

	/**
	 returns the number of match characters from begining,
	 the case sensitive comparison is always
	*/
	int find_common_part(const TCHAR* str);
	int find_common_part(MessageString* str);
};


#endif // _DYNAMIC_STRING_H_
