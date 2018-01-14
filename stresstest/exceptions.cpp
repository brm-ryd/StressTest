#include "mstring.h"
#include "exceptions.h"
#include "stdafx.h"

//**********************************************************
//********   implementation of class Exception  ************

//**********************************************************

bool Exception :: useFormattingMessageForCommandLine = false;

Exception :: Exception() {
	const TCHAR* s = "unexpected error";
   mes = new TCHAR[_tcslen(s) + 1];
	_tcscpy(mes, s);
}

Exception :: Exception(const TCHAR* message) {

	mes = new TCHAR[_tcslen(message) + 1];
	_tcscpy(mes, message);
}

Exception :: Exception(const TCHAR* message, const TCHAR* par1) {

	mes = new TCHAR[_tcslen(message) + _tcslen(par1) + 1];
	_stprintf(mes, message, par1);
}

Exception :: Exception(const TCHAR* message, const TCHAR* par1, const TCHAR* par2, const TCHAR* par3) {

	mes = new TCHAR[_tcslen(message) + _tcslen(par1) + _tcslen(par2) + _tcslen(par3) + 30];
	_stprintf(mes, message, par1, par2, par3);
}

Exception :: Exception(const TCHAR* message, int par1) {

	mes = new TCHAR[_tcslen(message) + 30 + 1];
	_stprintf(mes, message, par1);
}
Exception :: Exception(const TCHAR* message, const TCHAR* par1, int par2){

	mes = new TCHAR[_tcslen(message) + _tcslen(par1) + 31];
	_stprintf(mes, message, par1, par2);
}
Exception :: Exception(const TCHAR* message, int par1, const TCHAR* par2){

	mes = new TCHAR[_tcslen(message) + _tcslen(par2) + 31];
	_stprintf(mes, message, par1, par2);
}
Exception :: Exception(const TCHAR* message, int par1, int par2){

	mes = new TCHAR[_tcslen(message) + 61];
	_stprintf(mes, message, par1, par2);
}
Exception :: Exception(const TCHAR* message, const TCHAR* par1, const TCHAR* par2){

	mes = new TCHAR[_tcslen(message) + _tcslen(par1) + _tcslen (par2) + 1];
	_stprintf(mes, message, par1, par2);
}

Exception :: Exception(const TCHAR* message, const TCHAR* par1, int par2, const TCHAR* par3){

	mes = new TCHAR[_tcslen(message) + _tcslen(par1) + _tcslen (par3) + 31];
	_stprintf(mes, message, par1, par2, par3);
}


void Exception :: add(const TCHAR* message) {

	TCHAR* lmes = mes;
	mes = new TCHAR[_tcslen(lmes) + _tcslen(message) + 4];
	_tcscpy(mes, message);
	_tcscat(mes, _T(" : "));
	_tcscat(mes, lmes);
	delete[] lmes;
}

void Exception :: add(const TCHAR* message, const TCHAR* par1) {

	TCHAR* lmes = mes;
	mes = new TCHAR[_tcslen(mes) + _tcslen(message) + _tcslen(par1) + 4];
	_stprintf(mes, message, par1);
	_tcscat(mes, _T(" : "));
	_tcscat(mes, lmes);
	delete[] lmes;
}
void Exception :: add(const TCHAR* message, int par1) {

	TCHAR* lmes = mes;
	mes = new TCHAR[_tcslen(mes) + _tcslen(message) + 30 + 4];
	_stprintf(mes, message, par1);
	_tcscat(mes, _T(" : "));
	_tcscat(mes, lmes);
	delete[] lmes;
}
void Exception :: add(const TCHAR* message, const TCHAR* par1, int par2){

	TCHAR* lmes = mes;
	mes = new TCHAR[_tcslen(mes) + _tcslen(message) + _tcslen(par1) + 34];
	_stprintf(mes, message, par1, par2);
	_tcscat(mes, _T(" : "));
	_tcscat(mes, lmes);
	delete[] lmes;
}
void Exception :: add(const TCHAR* message, int par1, const TCHAR* par2){

	TCHAR* lmes = mes;
	mes = new TCHAR[_tcslen(mes) + _tcslen(message) + _tcslen(par2) + 34];
	_stprintf(mes, message, par1, par2);
	_tcscat(mes, _T(" : "));
	_tcscat(mes, lmes);
	delete[] lmes;
}
void Exception :: add(const TCHAR* message, int par1, int par2){

	TCHAR* lmes = mes;
	mes = new TCHAR[_tcslen(mes) + _tcslen(message) + 64];
	_stprintf(mes, message, par1, par2);
	_tcscat(mes, _T(" : "));
	_tcscat(mes, lmes);
	delete[] lmes;
}
void Exception :: add(const TCHAR* message, const TCHAR* par1, const TCHAR* par2){

	TCHAR* lmes = mes;
	mes = new TCHAR[_tcslen(mes) + _tcslen(message) + _tcslen(par1) + _tcslen (par2) + 4];
	_stprintf(mes, message, par1, par2);
	_tcscat(mes, _T(" : "));
	_tcscat(mes, lmes);
	delete[] lmes;
}

Exception :: ~Exception () {

	delete[] mes;
	//mes = 0;
}

TCHAR* Exception :: get_message() {

	return mes;
}

void Exception :: format() {

	UInt len =  (UInt)_tcslen(mes);
	for (UInt i = 0; i < len; i++) {

		if ((mes[i] == ':' && mes[i+1] == ' ') || i == 0) {

			if (i) {

				mes[i] = 10;
				if (useFormattingMessageForCommandLine) mes[i+1] = '\t';
			}
			#ifdef WIN32
			if (i) {
				if (mes[i+2]) {

					TCHAR* s;
					*(DWORD*)&s = (USHORT)mes[i+2];
					s = CharUpper(s);
					mes[i+2] = (TCHAR)*(DWORD*)&s;
				}
			}
			else {

				if (mes[i]) {

					TCHAR* s;
					*(DWORD*)&s = (USHORT)mes[i];
					s = CharUpper(s);
					mes[i] = (TCHAR)*(DWORD*)&s;
				}
			}
			#else
			if (i) {

				mes[i+2] = toupper(mes[i+2]);
			}
			else {

				mes[i] = toupper(mes[i]);
			}
			#endif
		}
	}
}

#ifdef WIN32

TCHAR* winerror(DWORD flags,int error) {

	static TCHAR errorString[1024];

   if (error == -1) error = GetLastError();

   FormatMessage(FORMAT_MESSAGE_IGNORE_INSERTS|FORMAT_MESSAGE_FROM_SYSTEM,
   0, error , 0, errorString, 1024, 0);

   if (flags & WE_PRINT) {

      _tprintf(errorString);
   }
   return errorString;
}

#endif
