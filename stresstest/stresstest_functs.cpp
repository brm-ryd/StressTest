//---------------------------------------------------------------------------
#define ETHERNET_ACCESS_DETAILS

#include "stdafx.h"
#include "stresstest_functs.h"
#include "reqandstat.h"
#include "stresstest_script.h"

#ifdef WIN32
#define write_to_file(x,y,z,p) WriteFile(x, y, z, (LPDWORD)p, 0)
#define read_from_file(x,y,z,p) WriteFile(x, y, z, (LPDWORD)p, 0)
char bufferForTranslateToOem[SIZE_OF_BUFFER_FOR_TRANSLATE_TO_OEM];
#endif

//TRACE_THREAD_INFO starting_threads_info[MAX_NUM_PORTS];

bool isWaitKeyPressBeforExit = false;
bool forcedTerm = false;
//ThreadToStopByTimeOutInfo threadToStopByTimeOutInfo;

#ifdef WIN32
HANDLE handleOfMainThread = 0;
#endif

// for getopt
char   *letP = NULL;
int	nextArgIndex	= 1;
char   *argumentForOption;

Network* globDevice;
ReqAndStat* globRas;
Script* globScript;


void registerGlobalObjects(Network* network, ReqAndStat* ras, Script* script) {
	globDevice = network;
	globRas = ras;
	globScript = script;
}


void signal_handler(int sig) {		

	userCheck(globDevice);
	userCheck(globScript);
	userCheck(globRas);
	
   for (UInt i = 0;  i < globDevice -> numOpenedInterfaces(); i++) {
      globDevice -> getInterface(i) -> setRequestToBreakTrace();
   }

	globRas -> setRequestForBreak();
	globScript -> setRequestForBreak();	

	if (forcedTerm) {		
		exit(0);
	}
}

int my_getopt(int argc, char *argv[], const char *optionS)
{
	unsigned char ch;
	char *optP;

	if (argc > nextArgIndex) {
		if (letP == NULL) {
			if ((letP = argv[nextArgIndex]) == NULL ||
				*(letP++) != GO_SW)  goto gopEOF;
			if (*letP == GO_SW) {
				nextArgIndex++;  goto gopEOF;
			}
		}
		if (0 == (ch = *(letP++))) {
			nextArgIndex++;  goto gopEOF;
		}
		if (':' == ch  ||  (optP = strchr((char*)optionS, ch)) == NULL)
			goto gopError;
		if (':' == *(++optP)) {
			nextArgIndex++;
			if (0 == *letP) {
				if (argc <= nextArgIndex)  goto  gopError;
				letP = argv[nextArgIndex++];
			}
			argumentForOption = letP;
			letP = NULL;
		} else {
			if (0 == *letP) {
				nextArgIndex++;
				letP = NULL;
			}
			argumentForOption = NULL;
		}
		return ch;
	}
gopEOF:
   argumentForOption = letP = NULL;
   return GO_EOF;

   gopError:
   argumentForOption = NULL;
   return ('?');
}

void myexit(int state, Exception* ex) {

	if (!ex) {

		
	}
	else {
	
		// exception reference is specified

		ex -> format();
		if (state && strlen(ex -> get_message())) {

			printf(ERROR_MESSAGE_FORMAT, ex -> get_message());
		}
	}

	if (isWaitKeyPressBeforExit)
	{
		printf("Press any key to continue");
      getch();
   }

	ADDTOLOG1("myexit -- start");

	// stops tracing (needed while terminating by Ctrl + C)	

	userCheck(globRas);	
   globRas -> stopTrace();	

	// for extra safety stopes threads for globalDevice although they may already be stoped by globalRas
   // ReqAndStat object may do it more carefully

	if (globDevice) {

      globDevice -> stopAllTrace();
	}

   mysleep(50); // it seems that pause is necessary after stoping of trace-treads befor calling to exit
                  // in order to avoid "segmentation fault"	

	#ifdef MYLOG
	globalLog.flush();
	#endif

   exit(state);
}


//#ifdef WIN32
//DWORD WINAPI thread_trace_to_file(LPVOID arg) {
//#else
//void* thread_trace_to_file(void *arg) {
//#endif
//
//	TRACE_THREAD_INFO* st;
//
//	st = (TRACE_THREAD_INFO*)arg;
//
//	try
//	{
//		trace_packets_to_file(st -> device, st -> interfaceNum, st -> catchfile);
//	}
//	catch (Exception* e) {
//
//		e -> format();
//		printf("error in tracing thread\n%s\n", e -> get_message());
//		printf("program may not further work correctly and must be terminated\nif program not respond you may terminate it by force\n");
//		delete e;
//	}
//
//   return 0;
//}


//#ifdef WIN32
//DWORD WINAPI threadToStopByTimeOut(LPVOID arg) {
//#else
//void* threadToStopByTimeOut(void *arg) {
//#endif
//
//	ThreadToStopByTimeOutInfo* info;
//	info = (struct ThreadToStopByTimeOutInfo*)arg;
//
//	mysleep(info -> timeout);
//
//	info -> device -> stop_trace(info -> interface_num);
//
//	return 0;
//}



//#ifdef WIN32
//DWORD WINAPI thread_wait(LPVOID arg) {
//#else
//void* thread_wait(void *arg) {
//#endif
//	WAIT_THREAD_INFO* st;
//   WAIT_HANDLER_INFO hi;
//
//	ADDTOLOG1("thread_wait -- starts tracing thread");
//
//   st = (WAIT_THREAD_INFO*)arg;
//
//	hi.ras = st -> ras;
//	hi.interfaceNum = st -> interfaceNum;
//
//	try
//	{
//		st -> dev -> trace(st -> interfaceNum, wait_handler, &hi);
//	}
//	catch(Exception* e) {
//
//		e -> format();
//		printf("error in tracing thread\n%s\n", e -> get_message());
//		printf("program may not further work correctly and must be terminated\nif program not respond you may terminate it by force\n");
//		delete e;
//	}
//
//	return 0;
//}


void trace_packets_to_file (Interface* interf, char* tracefile) {

	struct TRACE_TO_FILE_HANDLER_INFO tr_info;
	/** number of bytes written (only for Window) */
	u_int nw;
	int num = -1;

	// opens file

	#ifndef WIN32
	int f = open(tracefile,O_WRONLY|O_CREAT|O_TRUNC|O_BINARY,S_IWRITE|S_IREAD);
	if (!f) {
		 
		 throw new Exception("unable to open file '%s' for write : %s",tracefile, strerror(errno));
	}
	#else
	HANDLE f = CreateFile(tracefile, FILE_WRITE_DATA, FILE_SHARE_READ, 0, CREATE_ALWAYS,
		FILE_ATTRIBUTE_HIDDEN, 0);
	if (f == INVALID_HANDLE_VALUE) {

		throw new Exception("unable to open file '%s' for write : %s",tracefile, strerror(errno));		
	}
	#endif
	
	// determining unique name of interface
	for (int i=0; tracefile[i]; i++) {

		if (tracefile[i] >= '0' && tracefile[i]<='9') num = atoi(tracefile+i);
	}

	// writes libpcap header to trace file

	u_int b;
	b = 0xa1b2c3d4;
	write_to_file(f, &b, 4, &nw); // magic number
	b = 2;
	write_to_file(f, &b, 2, &nw); // minor version
	b = 4;
	write_to_file(f, &b, 2, &nw); // major version
	b = 0;
	write_to_file(f, &b, 4, &nw); // time zone offset
	b = 0;
	write_to_file(f, &b, 4, &nw); // time stamp accuracy
	b = 0xffff;
	write_to_file(f, &b, 4, &nw); // snapshot length
	b = 1;
	write_to_file(f, &b, 4, &nw); // link-layer type

	// starts tracing to file

	tr_info.device_num = num;
	tr_info.file_to_write = f;

	printf("Press <Ctrl + C> to stop. Tracing...\n");
   EthInterface* ei = dynamic_cast<EthInterface*>(interf);
   if (ei) {
      ei -> getCore() -> start_trace_eth(trace_to_file_handler, (void*)&tr_info);
   }
   else
      interf -> trace(trace_to_file_handler_light, (void*)&tr_info);
	
	close_file(f);		
}


void trace_to_file_handler (u_char *info, const struct pcap_pkthdr * h,
			     const u_char* pkt_data) {

	/** number of written bytes (Windows only) */
	u_int nw;
	FILE_HANDLE f = ((struct TRACE_TO_FILE_HANDLER_INFO*)info) -> file_to_write;
	//int num = ((struct TRACE_TO_FILE_HANDLER_INFO*)info) -> device_num;

	write_to_file(f,&h->ts, sizeof(h->ts),&nw);
	write_to_file(f,&h->caplen,sizeof(h->caplen),&nw);
	write_to_file(f,&h->len,sizeof(h->len),&nw);
	write_to_file(f,pkt_data,h->caplen,&nw);
	/*if (num != -1) {
		
		printf("%i",num);
	}
	else 
		printf("*");*/

	/*#ifdef WIN32
	FlushFileBuffers(f);
	#else
	fsync(f);
	//fflush(stdout);
	#endif*/
}

int trace_to_file_handler_light (u_char* pkt_data, u_int len, void* info) {
   struct timeval time = {0,0};	
   struct pcap_pkthdr h = { time, len ,len};
   trace_to_file_handler((u_char*)info,&h,pkt_data);
   return 0;
}

const char* getStringOfDump(const u_char* dump, int sizeOfDump) {

	static char bytesString[2500 * 2 + 1];

	if (sizeOfDump <= 1500) {

		bytesString[0] = 0;

		for (int i = 0; i < sizeOfDump; i ++) {

			sprintf(bytesString + i *  2, "%.2x", dump[i]);			
		}
	}
	else bytesString[0] = 0;

	return bytesString;
}


const char* getStringOfDump1(const u_char* dump, int sizeOfDump) {

	static char bytesString[2500 * 2 + 1];

	if (sizeOfDump <= 1500) {

		bytesString[0] = 0;

		for (int i = 0; i < sizeOfDump; i ++) {

			sprintf(bytesString + i *  2, "%.2x", dump[i]);			
		}
	}
	else bytesString[0] = 0;

	return bytesString;
}


void putValuesInMessage(MString& message, const Fields* fields, const Substitutions* substitutions, const FieldVariableValues* fieldVariableValues, const u_char* contentOfPacket, UInt sizePacBuf) {

	MString resultMessage;	
		
	UInt si = 0;
	UInt di = 0;
	for (; si < message.size(); ) {

		if (message[si] == '$') {

			UInt posFirstDollar = si;
			si ++;
			for (; message[si] != '$' && si < message.size(); si++);

			if (si != message.size() && si > posFirstDollar + 1) {

				bool found = false;
				MString nameOfItem;
				nameOfItem = message;
				
				nameOfItem.erase(0, posFirstDollar + 1);				
				nameOfItem.erase(si - posFirstDollar - 1, nameOfItem.size() - (si - posFirstDollar - 1));				
																																				  
				MString valueString = nameOfItem;

				// searches amoung fields
				if (!found && fields) {

					check(contentOfPacket);
					check(sizePacBuf != (UInt)-1)

					try
					{
						CommonField f(*fields, !nameOfItem);
						if (f.setByPacket(contentOfPacket, sizePacBuf) == ICR_OK) {
							valueString = f.getValueString(false);
						}

						found = true;
					}
					catch (Exception* e) {

						delete e;
					}					
				}

				// searches amoung substitutions
				if (!found && substitutions) {

					const char* s;
					s = substitutions -> search_value(!nameOfItem);
					if (s) {
						
						valueString = s;
						StresstestTextBuffer :: removeEnclosingCommas(&valueString);
						found = true;
					}
				}

				// searches amoung variables
				if (!found && fieldVariableValues) {

					const FieldVariableValue* var;
					var = fieldVariableValues -> getVariable_const(!nameOfItem, false);
					if (var) {
//						field -> getValueString(valueString, false);
                  valueString = var -> getValueConst().getValueString(false);
						found = true;
					}
				}
				
				if (!found) {

					throw new Exception("'%s' is not resolved", !nameOfItem);
				}

				resultMessage.insert(di, valueString);
				di += valueString.size();				

				si++;
				continue;				
			}
			else {

				if (message[si] != '$')
					si = posFirstDollar;
			}
		}
				
		resultMessage.resize(di + 1);
		resultMessage.at(di) = message[si];
		si++;
		di++;
	}

	resultMessage.resize(di);
		
	/*UInt res;
	while ((res = resultMessage.searchString("$$", 0)) != STRING_NOT_FOUND) {

		resultMessage.del(res, res);
	}*/

	message = resultMessage;
}
