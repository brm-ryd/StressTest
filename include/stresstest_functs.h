#ifndef STRESSTEST_FUNCTS_H
#define STRESSTEST_FUNCTS_H

#include "stresstest.h"
#include "logman.h"
#include "messagestring.h"
#include "network.h"
//#include "reqandstat.h"

#define MAX_CATCH_FILE_NAME 30
#define SIZE_ERR_DESC 1024

#ifdef WIN32
extern HANDLE handleOfMainThread;
#endif

extern bool forcedTerm;		// see signal_handler
// for all project
/** true - asks for pressing some key before exit (for Windows)
*/
extern bool isWaitKeyPressBeforExit;

class FieldVariableValues;
class Substitutions;
class Fields;
class Interface;

/** references to variables in stresstest_main.cpp */
extern int	nextArgIndex;
extern char *argumentForOption;

//typedef int (*ethernet_packet_handler)(u_char*, // packet's content
//	struct timeval, // packet's time
//	int caplen,		 // stored part of content (lenght of pkt_data)
//	int len,			 // real size of packet
//	void*);			 // additional user info (depends on concrete handler)

//typedef int (*an_packet_handler)(u_char*,u_int,void*);

/** information for trace_to_file_handler */
struct TRACE_TO_FILE_HANDLER_INFO {

	/** user number of interface */
	int device_num;
   /** file to write captured packets */
   FILE_HANDLE file_to_write;
};

/** information for thread_trace */
//struct TRACE_THREAD_INFO
//{
//	Network* device;
//	int interfaceNum;
//   stresstest_packet_handler handler;
//   void* userData;
//	/** name of file to write captured packets */
//	//char catchfile[MAX_CATCH_FILE_NAME];
//};

/** information for thread_wait */
//struct WAIT_THREAD_INFO {
//
//	/** work device */
//	Network* dev;
//	/** word interface of device */
//	int interfaceNum;
//	/** work ReqAndStat object */
//	ReqAndStat* ras;
//};

/** information for wait_handler */
struct WAIT_HANDLER_INFO {

	ReqAndStat* ras;
	int interfaceNum;
};

//struct ThreadToStopByTimeOutInfo {
//
//	int interface_num;
//	Network* device;
//	UInt timeout;
//};

//extern ThreadToStopByTimeOutInfo threadToStopByTimeOutInfo;
//extern TRACE_THREAD_INFO starting_threads_info[];

// *********************************************************
// ************** FUNCTIONS PROTOTYPES *********************
// *********************************************************


//#ifdef WIN32
//DWORD WINAPI threadToStopByTimeOut(LPVOID arg);
//#else
//void* threadToStopByTimeOut(void *arg);
//#endif

void registerGlobalObjects(Network* network, ReqAndStat* ras, Script* script);

/** terminating program with performing additional operations  */
void myexit(int state, Exception* ex = 0);

/**
 function trace_packets_to_file,
 starts tracing packets with storing in trace-file
*/
void trace_packets_to_file (Interface* dev, // device
									char* tracefile // file's name
									);

/**
 packet handler which writes packet to trace-file,
 * must comply with libpcap packet_handler
 always returns 0
*/
void trace_to_file_handler (u_char *info, const struct pcap_pkthdr * h,
			     const u_char* pkt_data);

int trace_to_file_handler_light (u_char* pkt_data, u_int len, void* info);


/** forms string from array of bytes, string is a sequence of hexadecimal numbers */
const char* getStringOfDump(const u_char* dump, int sizeOfDump);
const char* getStringOfDump1(const u_char* dump, int sizeOfDump);	// uses another global buffer

/** is similar to Script :: putValuesInMessage */
void putValuesInMessage(
								MessageString& message,
								const Fields* fields = Null,
								const Substitutions* substitutions = Null,
								const FieldVariableValues* fieldVariableValues = Null,
								const u_char* contentOfPacket = Null,
								UInt sizePacBuf = (UInt)-1
								);

// thread thread_wait
// starts tracing using method Network :: start_trace
// as argument receives a pointer to WAIT_THREAD_INFO struct

// thread thread_trace
// starts tracing using function trace_packets_to_file
// as argument receives a pointer to TRACE_THREAD_INFO struct

#ifdef WIN32
//DWORD WINAPI thread_trace_to_file(LPVOID arg);
//DWORD WINAPI thread_wait(LPVOID arg);
void  signal_handler(int sig);
#else
//void* thread_trace_to_file(void *arg);
//void* thread_wait(void *arg);
void signal_handler(int sig);
#endif

#define GO_SW '-'
#define GO_EOF (-1)
// analog of UNIX function for WINDOWS
int my_getopt(int, char **, const char *);

#endif
