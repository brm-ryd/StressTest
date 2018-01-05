#ifndef STRESSTEST_H
#define STRESSTEST_H

#ifdef HAVE_CONFIG_H

   #include "config.h"

#endif

#ifdef DEBUG
#define TEST_MODE
#endif

#ifdef WIN32 // WINDOWS defined

   #define WINVER 		0x0501
	#define _WIN32_WINNT 0x0501

	#include <winsock2.h>
	#include <ws2tcpip.h>

	#include <sys/types.h>
	#include <sys/stat.h>
	#include <fcntl.h>
	#include <io.h>
	#include <conio.h>	
	#include <errno.h>
	#include <process.h>
	
	#include <dos.h>
	#include <math.h>  
   #include <signal.h>

	#include <iostream>
	#include <sstream>
	#include <fstream>
	#include <string>
	#include <vector>

	using namespace std;	

	#define strCaseCompare(x, y) _tcsicmp(x, y)
	//#define strCaseCompare(x, y) CompareString(LOCALE_SYSTEM_DEFAULT, NORM_IGNORECASE, x, lstrlen(x), y, lstrlen(y))

	#define mysleep(x) Sleep(x)

	#define FILE_HANDLE HANDLE

	#ifdef printf
	#undef printf
	#endif

	#define SIZE_OF_BUFFER_FOR_TRANSLATE_TO_OEM 20480
	extern char bufferForTranslateToOem[];

	#define printf(...) {\
		snprintf(bufferForTranslateToOem, SIZE_OF_BUFFER_FOR_TRANSLATE_TO_OEM, __VA_ARGS__);\
		CharToOem(bufferForTranslateToOem, bufferForTranslateToOem);\
		printf("%s",bufferForTranslateToOem);\
	}

	#define close_file(x) CloseHandle(x)

	#define DB(x)	;

//	#pragma warning(disable:4996)
//	#pragma warning(disable:4267)
//	#pragma warning(disable:4018)
//	#pragma warning(disable:4290)

	/*#pragma warning(error:4101)
	#pragma warning(error:4244)
	#pragma warning(error:4800)*/

#else   // UNIX defined

	#include <stdio.h>
	#include <string.h>
	#include <sys/types.h>
	#include <sys/stat.h>
	#include <fcntl.h>
	#include <errno.h>
	#include <unistd.h>
	#include <netinet/in.h>
	#include <sys/socket.h>
	//#include <netpacket/packet.h>
	#include <net/ethernet.h>
	#include <stdlib.h>
	#include <pthread.h>
	#include <curses.h>
	#include <netdb.h>
   #include <signal.h>
	#include <ctype.h>

	#include <iostream>
	#include <sstream>
	#include <fstream>
	#include <string>
	#include <vector>
 
	#define strCaseCompare(x, y) strcasecmp(x,y)

	#define mysleep(x) usleep(x*1000)

	typedef pthread_t HANDLE;

	#define O_BINARY 0

	#define write_to_file(x,y,z,o) write(x, y, z)
	#define read_from_file(x,y,z,o) write(x, y, z)

	#define FILE_HANDLE int

	#define close_file(x) close(x)
		
	#define DB(x) ;

	typedef bool boolean;

#endif  // WIN32

#define STRESSTEST_VERSION "1.1"
#define STRESSTEST_BUILD 	 "4"

//#define SSPT2_BUG

#define MAX_NUM_PORTS 30 // maximum number of interfaces of any type (ethernet, tcp, trace files)
	
#define ERROR_MESSAGE_FORMAT "\nERROR:\n\t%s\n\n"

#ifdef WIN32
typedef unsigned char u_char;
typedef unsigned short u_short;
#endif

typedef unsigned short ushort;
typedef unsigned int uint;
typedef unsigned char uchar;

#define Null NULL

class Network;
class ErrorDesc;
class Script;
class SequenceOfPackets;
class Paths;
class Fields;
class ReqAndStat;
class Substitutions;
class FieldMask;
class CustomPacketField;
class Exception;
class EthDevice;
class IPDevice;
class TCPDevice;
class UDPDevice;
class TraceFile;
class AutocalcManager;
class CommandsProcessor;

struct EndPoint;
struct TimeStamp;

#endif // STRESSTEST_H
