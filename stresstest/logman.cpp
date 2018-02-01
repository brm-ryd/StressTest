#include "stdafx.h"
#include "logman.h"

#ifdef WIN32

Logman globalLog;
ostringstream globalLogStream;

TCHAR Logman :: buffer[] = _T("");

void Logman :: flush() {

	//return;
	try
	{

	//ADDTOLOG("Hello World %i", "ss");

	check(WAIT_OBJECT_0 == WaitForSingleObject(multipleThreadsAccess, INFINITE));

	if (records.size() == 0) {

		ReleaseMutex(multipleThreadsAccess);
		return;
	}

	HANDLE logFile = CreateFile(!filename, GENERIC_WRITE, FILE_SHARE_READ,
		NULL, OPEN_ALWAYS,
		0, NULL);

	if (logFile == INVALID_HANDLE_VALUE)
		throw new Exception(_T("error opening '%s' for appending data : %s"), !filename, winerror(0));

	DWORD fileSize = GetFileSize(logFile, NULL);

	if (fileSize != 0xFFFFFFFF && fileSize > 10 * 1024 * 1024) {

		SetEndOfFile(logFile);
	}
	else
		SetFilePointer(logFile, 0, 0, FILE_END);

	try
	{

		DWORD numWrittenBytes;
		vector<MessageString>::iterator it = records.begin();
		for (; it != records.end(); it++) {

			//MessageString curRecord = *it;
			check(WriteFile(logFile, !(*it), it -> len(), &numWrittenBytes, 0));
			check(WriteFile(logFile, "\r\n", 2, &numWrittenBytes, 0));
		}
		}
		catch (Exception* e) {

			CloseHandle(logFile);
			throw e;
		}

		CloseHandle(logFile);
		records.clear();
	}

	catch (Exception* e) {

		MessageString processName;
		MessageString mes;

		ReleaseMutex(multipleThreadsAccess);

		mes = _T("error while flushing log to file '");
		mes.append(!filename);
		mes.append(_T("' : "));
		mes.append(e -> get_message());

		processName.resize(MAX_PATH);
		processName.at(GetModuleFileName(NULL, (TCHAR*)!processName, MAX_PATH)) = 0;

		MessageBox(NULL, !mes, (TCHAR*)!processName, MB_ICONERROR|MB_OK);

		delete e;
	}

	ReleaseMutex(multipleThreadsAccess);
}

void Logman :: add(const TCHAR* str) {

	MessageString finalString;
	MessageString systemDateString;
	MessageString systemTimeString;
	SYSTEMTIME systemTime;
	GetLocalTime(&systemTime);

	//if (WaitForSingleObject(multipleThreadsAccess, INFINITE) == WAIT_ABANDONED)
	//	Test();

	systemTimeString.resize(30);
	systemTimeString.resize(GetTimeFormat(LOCALE_SYSTEM_DEFAULT, LOCALE_NOUSEROVERRIDE, &systemTime,
		0,
		//"HH':'mm':'ss':'",
		(TCHAR*)!systemTimeString, 30) - 1);

	_stprintf((TCHAR*)systemTimeString.c_str() + systemTimeString.size(), _T(":%hu"), systemTime.wMilliseconds);

	systemDateString.resize(30);
	systemDateString.resize(GetDateFormat(LOCALE_USER_DEFAULT, LOCALE_NOUSEROVERRIDE, &systemTime,
		//"dd'-'MM'-'y"
		0, (TCHAR*)!systemDateString, 30) - 1);

	finalString = systemDateString;
	finalString.append(_T(" "));
	finalString.append(!systemTimeString);

	finalString.append(_T(" -- "));
	finalString.append(str);

	addRecordAsString(!finalString);

	if (records.size() > maxNumberOfRecords) flush();
}

#endif //WIN32
