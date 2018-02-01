#include "stresstest.h"
#include "messagestring.h"
#include "stresstest_script.h"
#include "network.h"
#include "stresstest_config.h"
#include "paths.h"
#include "stresstest_functs.h"
#include "reqandstat.h"
#include "tracefile.h"
#include "protocolsExpert.h"
#include "tcpip.h"
#include "extend_helper.h"

#ifdef TEST_MODE

	#include "testing.h"

#endif

//---------------------------------------------------------------------------

#define USAGE_STR1 \
"StressTest - tool for automated testing of network devices and applications\n\
Usage: stresstest \n\n\
      {-d <interface's name>}\n\
      [-f <stresstest script file>]\n\
      {-c <trace file>}\n\
      [-t <trace file to write> ]\n\
      [-T <timeout for server in ms>]\n\
      {-I<path where search for headers>}\n\
		[-k] [-p] [-v] [-i] [-w] [-r] [-q] [-s <snaplen>] [-u <ms>]\n\
      [stresstest script text]\n\n\
Description:\n\
  -i     Outputs info about network interfaces at channel level\n\
  -d     Network interface to work specified by its name.\n\
         Interface's name: eth0, 1.1.1.1, localhost, client:pop3.mail.ru:110.\n\
         After symbol # user's unique name of interface may be specified (ex: eth0#0).\n\
         If not given then it'll be assigned to number 0,1,2,...\n\
  -f     Text file containing script to process.\n\
         The script may also be given directly in command line.\n\
  -T     Instructs to work with a TCP session.\n\
         Interface's name must have the following format: <direction>:<host>:<port>.\n\
         <direction> = \"client\" | \"server\"\n\
         Ex: client:pop3.mail.com:110, server:localhost:110\n\
         Client mode: attempts to establish connection to the given server.\n\
         Server mode: binds to the given port on localhost and waits for connections.\n\
         Argument specifies the timeout while listening in server mode. 0 means infinite waiting.\n\
  -c     Specifies a trace file for compare regime. Trace files will be used as interfaces.\n\
  -t     Specifies a trace file to store captured packets.\n\
  -I     Adds the path where to search for header files (\"headers\" folder must exist there).\n\
  -v     Verbose output while displaying the report\n\
  -w     Asks for keypress before terminating\n\
  -q     Forces NOT promisc mode\n\
  -k     Show fields info (from headers). The list of header's names must be specified.\n\
  -r     Scanner regime. Realtime capturing with periodic displaying of report.\n\
  -p     Instructs to use RAW IP. Note: there are many restrictions in this mode.\n\
  -s     Snaplen (UNIX only)\n\
  -u     Update interval in scanner regime (1000 ms by default)\n\n\
Examples:\n\n\
 stresstest -d <interface> -f script.fws          Common regime\n\
                                                (sending/waiting packets\n\
                                                following the given script)\n\n\
 stresstest -i                                    Lists interfaces\n\
                                                (when using libpcap/winpcap)\n\n\
 stresstest -d <interface> -t file.pcap           Captured packets will be\n\
                                                written to file.pcap\n\n\
 stresstest help all exit 0                       Prints the list of commands\n\n\
 stresstest -f script.fws -c captured.pcap        Searches packets from script.fws\n\
                                                in captured.pcap\n\n\
 stresstest -r -f script.fws -d <interface>       Realtime capturing packets\n\
                                                from script.fws\n\n\
\n\
 Return: 0 - test completed and successful\n\
         1 - fatal error, test not completed and have no result\n\
         2 - test completed but not successful\n\n"


#define OPTION_STRING "f:c:d:vit:rpwqI:T:u:ks:"

const char USAGE_STR[] = {"version " STRESSTEST_VERSION " build" STRESSTEST_BUILD "\n" "compiled " __DATE__ " " __TIME__ "\n"
   USAGE_STR1};

// the following objects are declared globally in order to their destructors ALWAYS be called when program terminates

EthDevice globalEthernetDevice;
IPDevice globalIPDevice;
TCPDevice globalTCPDevice;
UDPDevice globalUDPDevice;

Network networkg;
Network* globalDevice = &networkg;

ReqAndStat globalRas;

int main(int argc, char* argv[])
{
	int i;
	char* scrfile;
	char* file_to_trace;
	bool showFieldsInfo = false;
	bool catch_file_given = false,
        rec_mode = false,
        scriptInArgs = false;

	try
	{
		AutocalcManager autocalcManager;
		TraceFile globalTraceFile;
		Script globalScript(*globalDevice, globalRas, globalTraceFile, autocalcManager, SR_NOINIT);

		registerGlobalObjects(globalDevice, &globalRas, &globalScript);

		vector<Device*> devices = ExtendHelper :: getNetworkDevices();
		devices.push_back(&globalEthernetDevice);
		devices.push_back(&globalIPDevice);
		devices.push_back(&globalTCPDevice);
		devices.push_back(&globalUDPDevice);
		globalDevice->setDevices(devices);

		StresstestTextBuffer :: setKnownValueTypes(ExtendHelper :: getValueTypes());
		autocalcManager.setProtocolExperts(ExtendHelper :: getProtocolsExperts());
		globalScript.setCommandProcessors(ExtendHelper :: getCommandProcessors());

		ADDTOLOG1("main -- start");

		ProtocolsExpert*  pe;
		//pe = new fie;

		//globalLog.setMaxNumberOfRecords(1);
		#ifndef STRESSTEST_FAST
		MessageString :: caseSensitive = false;
		#else
		MessageString :: caseSensitive = true;
		#endif
		Exception :: useFormattingMessageForCommandLine = true;

	#ifdef WIN32
		handleOfMainThread = GetCurrentThread();
		MessageString :: caseSensitiveForUseLocale = false;
	#endif

		StresstestConfig conf;
		MessageString script_str;

		//PlaySound("Windows XP Notify.wav", Null, SND_FILENAME|SND_ASYNC);


		// initializes random numbers generator

		#ifdef WIN32
		srand((int)GetTickCount());
		#else
		struct timeval time;
		gettimeofday(&time, 0);
		srand(time.tv_sec);
		#endif

		// sets siganl handler

		if (SIG_ERR == signal(SIGINT, signal_handler)) {
         throw new Exception("system : setting the disposition of SIGINT signal");
		}

		#ifdef WIN32
		init_wsa();  // for Windows initializes WSA (sockets)
		#endif

      string devName = globalEthernetDevice.gettype();

		// PARSES COMMAND LINE

		scrfile=0;
		file_to_trace = 0;

		// first level options

		while ( (i=my_getopt(argc,argv,OPTION_STRING)) != EOF) {

			if (i=='w') {

				isWaitKeyPressBeforExit = true;
			}

			if (i == 's') {

				MessageString s;
				UInt n;
				s = argumentForOption;
				try
				{
					n = (UInt)s.getNumber(true, true);
				}
				ADD_TO_ERROR_DESCRIPTION("reading snaplen size");

				EthDevice :: setDefaultSanpLen(n);
			}

			if (i=='?') break;  // error
		}

		// second level options

		nextArgIndex = 1;

		while ( (i=my_getopt(argc,argv,OPTION_STRING)) != EOF) {

			if (i == 'p') {   // using IP device

            devName = globalIPDevice.gettype();
			}

			if (i == 'T') {  // using Tcp device

				devName = globalTCPDevice.gettype();

				MessageString s = argumentForOption;
				UInt t;
				try
				{
					t = (UInt)s.getNumber(true, true);
				}
				ADD_TO_ERROR_DESCRIPTION("reading the value of timeout for option -T");

            if (t)
					TCPDevice :: timeoutInMilliseconds = t;
            else
					TCPDevice :: timeoutInMilliseconds = INFINITE_WAITING;
			}

			if (i == 'q') {  // disable promisc mode

				globalEthernetDevice.setPromisc(0);
			}

			if (i == 'I') {      // add the new path to search headers and samples

				globalScript.add_include_path(argumentForOption);
			}

			if (i=='?') break;
		}

		// third level options

		nextArgIndex = 1;

		while ( (i=my_getopt(argc,argv,OPTION_STRING)) != EOF) {

			if (i == '?') {

				printf("%s",USAGE_STR);
				throw new Exception("error in parameters");
			}

			if (i == 'u') {

				int t;
				t = atoi(argumentForOption);
				if (!t) {

					throw new Exception("option -u : need number as argument");
				}
				globalRas.set_update_interval(t);
			}

			if (i == 'r') {      // sets sniffers mode

      		rec_mode = true;
			}

			if (i == 'i') {  // displays adapters info

				globalEthernetDevice.printAdaptersInfo();

				exit(0);
			}

			if (i == 'f') scrfile = argumentForOption;

			if (i == 'c') {

				globalRas.addNewTraceFile(argumentForOption);

				catch_file_given = true;
			}

			if (i == 't') {  // receiving captured packets to file

				file_to_trace = argumentForOption;
			}

			if (i == 'd') {   // opening adapter

				globalDevice -> openInterface(devName, MessageString(argumentForOption));
			}

			if (i == 'v') globalRas.verbose = true;  // verbose reports

			if (i == 'k') {

				showFieldsInfo = true;
			}
		}

#ifdef WIN32

		try
		{
			// reads global configuration

			conf.read();

			// adds a new search path from configuration

			if (conf.get_base_path()) {

				globalScript.add_include_path(conf.get_base_path());
			}
			else {

				throw new Exception("default path with headers and samples not specified : you will need to use option -I");
			}

			if (globalDevice -> numOpenedInterfaces() == 0) {

				// user has not specified the type of device and has not opened any interface

				// reads default type of device and interface from configuration

            globalDevice -> openInterface(
               MessageString(conf.get_device_type()),
               MessageString(conf.get_def_device())
            );

				// initializing the device if it's not Ethernet

//				switch (dev_type) {
//
//					case DT_IP:  globalDevice = (Network*)&globalIPDevice;
//									 break;
//
//					case DT_TCP: globalDevice = (Network*)&globalTCPDevice;
//									 break;
//				}

				// opening interface


//				if (globalDevice -> gettype() == DT_ETH || globalDevice -> gettype() == DT_TCP)
//
//					if (conf.get_def_device()) {
//						globalDevice -> openInterface(MessageString(conf.get_def_device()));
//				}
			}
		}

		catch (Exception* e) {

			e -> format();
			printf("\nWarning: error while reading configuration info from registry\n\t%s\nUse \"registry.reg\" file from distribute.\n\n", e -> get_message());
			delete e;
		}

#else
		check(conf.get_base_path());
		globalScript.add_include_path(conf.get_base_path());
#endif

		// parses the rest of command line: the content of script
		while (nextArgIndex < argc) {

			scriptInArgs = true;

			// if the argument has spaces within then must be enclosed by apostrophes

			if (strchr(argv[nextArgIndex],' ')) {

				script_str.append("'");
			}

			script_str.append(argv[nextArgIndex]);	 // adds to script_str

			if (strchr(argv[nextArgIndex],' ')) {

				script_str.append("'");
			}

			script_str.append(" ");
			nextArgIndex ++;
		}

      globalScript.set_device(globalDevice, 0);
		globalRas.set_device(globalDevice);

      #ifdef TEST_MODE

         Testing :: runAllTests();

      #endif

		//******************************************************
		//******************************************************
		//					sniffer mode
		//******************************************************
		//******************************************************

		if (rec_mode) {

			if (globalDevice -> numOpenedInterfaces() == 0) {

				throw new Exception("need at least one device (-d option)");
			}

			if (!scrfile && !scriptInArgs) {

				throw new Exception("need script file (option -f) or desription of packets in command line");
			}

			globalScript.reset(SR_SNIFFER);

			// processing script

			if (scrfile) {

				// ... from file
				globalScript.processFile(scrfile);
			}
			else {

				// ... from command-line
				check(scriptInArgs);

				script_str.append(" SEND");
				globalScript.run("command line", !script_str);
			}

			// works with globalRas

			globalRas.startConcurrentSniffersOnInterfaces();

			globalRas.displayPeriodicReports();

			myexit(globalRas.getLastStatus());
		}

		// ****************************************************************************
		// ****************************************************************************
		//			Common mode	(or online-test of packet filter, command FASTTEST)
		// ****************************************************************************
		// ****************************************************************************

		if ((scrfile || scriptInArgs) && !catch_file_given) {

			if (scriptInArgs && !showFieldsInfo) {

				// adds command SEND to the end of packet's description in command-line

				script_str.append(" SEND");
			}

			globalRas.startConcurrentSniffersOnInterfaces();

			mysleep(PAUSE_BEFOR_GENERATING);

			// processing script

			globalScript.reset(SR_GEN);

			if (scrfile) {

				// from file

				globalScript.processFile(scrfile);
			}
			else {

				// from command-line

				globalScript.run("command line", !script_str);
			}

			// while fasttest regime we must slightly delayed in order to last packets may be registered by sniffers
			if (globalScript.isFasttestWasSpecified()) mysleep(PAUSE_AFTER_GENERATING);

			// displays statistic

			if (globalRas.isAnyRequestsWereSpecified()) {

				globalRas.showStatictic();
			}

			if (showFieldsInfo) {

				globalScript.printFieldsInfo();
			}

			myexit(globalRas.getLastStatus());
		}

		//*******************************************************
		//*******************************************************
		//			Recording captured packets to file
		//*******************************************************
		//*******************************************************

		if (!scrfile) {

			if (!file_to_trace) {

				printf("%s", USAGE_STR);
				throw new Exception("trace file (option -t) or script file (option -f) must be specified : (or script text in command line)");
			}

			if (!globalDevice -> numOpenedInterfaces()) {

				throw new Exception("some device must be specified for tracing (option -d)");
			}

			forcedTerm = true;

			try
			{
				trace_packets_to_file(globalDevice -> getInterface(0), file_to_trace);
			}
			ADD_TO_ERROR_DESCRIPTION("while start tracing to file");

			myexit(0);
		}

		//******************************************************
		//******************************************************
		//		WORKS WITH TRACE FILES (option -c is specified)
		//******************************************************
		//******************************************************

		globalScript.set_device(globalDevice,0);

		// processes script

		globalScript.reset(SR_STAT);
		globalScript.processFile(scrfile);

		// displays statistic

		globalRas.fill_stat(FS_USEFILES);
		globalRas.showStatictic();

		myexit(globalRas.getLastStatus());
	}

	catch (SocketInterface :: SendingOverSocketException* e) {

		myexit(3, e);
	}

	catch (SocketInterface :: ConnectionFailedException* e) {

		myexit(3, e);
	}

	catch (Exception* e) {

		myexit(1, e);
	}

	catch (std::bad_alloc &ba) {

		printf("Error while allocating memory : %s\n", ba.what());
		myexit(1, 0);
	}
}
//---------------------------------------------------------------------------
