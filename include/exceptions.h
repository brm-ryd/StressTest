#ifndef _EXCEPTIONS_H_
#define _EXCEPTIONS_H_

#ifdef HAVE_CONFIG_H
   #include "config.h"
#endif

#ifdef WIN32
#include <windows.h>
#else
#include <ctype.h>
#endif

#include <stdio.h>
#include <string.h>

#ifdef WIN32
#include <tchar.h>
#else
#define _T(x) x
#define TCHAR char
#define _tcslen strlen
#define _tcscat strcat
#define _stprintf sprintf
#define _tcscpy strcpy
#define _tcscmp strcmp
#define _tcstod strtod
#endif

#ifdef UNICODE
#define string wstring
#endif

#define UChar unsigned char

#define THROW_INTERNAL_ERROR { throw new Exception(_T("internal error, file %s, line %i"), _T(__FILE__), __LINE__); }

#define Test() { throw new Exception(_T("Unexpected error - File %s - line %d"), _T(__FILE__), __LINE__); }

#define check(x) if (!(x)) throw new Exception(_T("Unexpected error - File %s - line %d"), _T(__FILE__), __LINE__);
#define systemCheck(x) if (!(x)) throw new Exception(_T("System error - File %s - line %d"), _T(__FILE__), __LINE__);
#define memCheck(x) if (!(x)) throw new Exception(_T("Error while allowing memory - File %s - line %d"), _T(__FILE__), __LINE__);
#define userCheck(x) if (!(x)) throw new Exception(_T("Error - File %s - line %d"), _T(__FILE__), __LINE__);

typedef unsigned int UInt;
typedef unsigned int  u_int;

typedef unsigned short UShort;
typedef unsigned short u_short;

#define ADD_TO_ERROR_DESCRIPTION(x)      catch(Exception* e) { e -> add(x); throw; }
#define ADD_TO_ERROR_DESCRIPTION2(x,y)   catch(Exception* e) { e -> add(x,y); throw; }
#define ADD_TO_ERROR_DESCRIPTION3(x,y,z) catch(Exception* e) { e -> add(x,y,z); throw; }

#ifdef WIN32
// for 'winerror' function
#define WE_PRINT 0x1

/** returned pointer may be used only for next call to this function */
TCHAR* winerror(
	DWORD flags = 0,  // WE_
	int error=-1 // from GetLastError()
	);
#endif


class Exception  {

public:

	static bool useFormattingMessageForCommandLine;

private:

	TCHAR* mes;

public:

	Exception();
	Exception(const TCHAR* message);
	Exception(const TCHAR* message, const TCHAR* par1);
	Exception(const TCHAR* message, int par1);
	Exception(const TCHAR* message, const TCHAR* par1, int par2);
	Exception(const TCHAR* message, int par1, const TCHAR* par2);
	Exception(const TCHAR* message, int par1, int par2);
	Exception(const TCHAR* message, const TCHAR* par1, const TCHAR* par2);
	Exception(const TCHAR* message, const TCHAR* par1, int par2, const TCHAR* par3);
	Exception(const TCHAR* message, const TCHAR* par1, const TCHAR* par2, const TCHAR* par3);

	void add(const TCHAR* message);
	void add(const TCHAR* message, const TCHAR* par1);
	void add(const TCHAR* message, int par1);
	void add(const TCHAR* message, const TCHAR* par1, int par2);
	void add(const TCHAR* message, int par1, const TCHAR* par2);
	void add(const TCHAR* message, int par1, int par2);
	void add(const TCHAR* message, const TCHAR* par1, const TCHAR* par2);

	~Exception();

	TCHAR* get_message();
	void format();

};


class OutOfBufferBorders : public Exception {

public:

	OutOfBufferBorders() : Exception (_T("not allowed attempt to access out of buffer's borders")) {}
};


 #endif // _EXCEPTIONS_H_
