#ifndef _LOGMAN__
#define _LOGMAN__

#ifdef HAVE_CONFIG_H
   #include "config.h"
#endif

#ifndef WIN32

#define ADDTOLOG(x) { ; }
#define ADDTOLOG1(x1) { ; }
#define ADDTOLOG2(x1, x2) { ; }
#define ADDTOLOG3(x1, x2, x3) { ; }
#define ADDTOLOG4(x1, x2, x3, x4) { ; }
#define ADDTOLOG5(x1, x2, x3, x4, x5) { ; }

#else

//class List;

#include <iostream>
#include <sstream>
#include <vector>
#include "string.h"
#include "mstring.h"

class Logman;

#ifdef MYLOG

#define ADDTOLOG(x, ...) { _snprintf(Logman :: buffer, SIZE_OF_BUFFER_FOR_LOG, x, __VA_ARGS__); globalLog.add(Logman :: buffer); }

#define ADDTOLOG1(x) { globalLog.add(x); }
//#define ADDTOLOG2(x1, x2) { sprintf(Logman :: buffer, x1, x2); ADDTOLOG(Logman :: buffer); }
//#define ADDTOLOG3(x1, x2, x3) { sprintf(Logman :: buffer, x1, x2, x3); ADDTOLOG(Logman :: buffer); }
//#define ADDTOLOG4(x1, x2, x3, x4) { sprintf(Logman :: buffer, x1, x2, x3, x4); ADDTOLOG(Logman :: buffer); }
//#define ADDTOLOG5(x1, x2, x3, x4, x5) { sprintf(Logman :: buffer, x1, x2, x3, x4, x5); ADDTOLOG(Logman :: buffer); }

#else

#define ADDTOLOG(x, ...) { ; }
#define ADDTOLOG1(x) { ; }
//#define ADDTOLOG(x,...) { ; }
//#define ADDTOLOG2(x1, x2) { ; }
//#define ADDTOLOG3(x1, x2, x3) { ; }
//#define ADDTOLOG4(x1, x2, x3, x4) { ; }
//#define ADDTOLOG5(x1, x2, x3, x4, x5) { ; }

#endif

#define ADDTOLOG2(x1, x2) ADDTOLOG(x1,x2)
#define ADDTOLOG3(x1, x2, x3) ADDTOLOG(x1,x2,x3)
#define ADDTOLOG4(x1, x2, x3, x4) ADDTOLOG(x1,x2,x3,x4)
#define ADDTOLOG5(x1, x2, x3, x4, x5) ADDTOLOG(x1,x2,x3,x4,x5)

//#define debug(format, ...) fprintf (stderr, format, __VA_ARGS__)

#define ADDLOG(x) { globalLogStream.clear(); globalLogStream << x; globalLog.add(globalLogStream.str()); }
//#define ADDLOG() { ; }

extern Logman globalLog;

extern ostringstream globalLogStream;

#define SIZE_OF_BUFFER_FOR_LOG 8192

class Logman {

public:

	static TCHAR buffer[SIZE_OF_BUFFER_FOR_LOG];

private:

	MString filename;
	vector<MString> records;
	HANDLE multipleThreadsAccess;
	UInt maxNumberOfRecords;

	void addRecordAsString(const TCHAR* str) {

		WaitForSingleObject(multipleThreadsAccess, INFINITE);

		MString s;
		s.assign(str);
		records.push_back(s);

		ReleaseMutex(multipleThreadsAccess);
	}

public:

	Logman() {

		multipleThreadsAccess = CreateMutex(NULL, false, NULL);
		check(multipleThreadsAccess);

		maxNumberOfRecords = 1000;
		filename = _T("log.txt");
	}

	~Logman() {

		flush();

		DeleteObject(multipleThreadsAccess);
	}

	void setMaxNumberOfRecords(UInt n) {

		maxNumberOfRecords = n;
	}

	/** clear content in memory after appending to file 'filename' on disk */
	void flush();

	/**
	 add new message, if messages are more than 'maxNumberOfRecords' then calls 'flush',
	 adds time and date to message
	*/
	void add(const TCHAR* str);

	void add(const string& str) {

		add(str.c_str());
	}
};

#endif //WIN32

#endif //_LOGMAN__
