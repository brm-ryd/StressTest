#define ETHERNET_ACCESS_DETAILS


#include "stresstest.h"
#include "logman.h"
#include <pcap.h>
#include "network.h"


boolean Network :: quiet = false;

/**
 searches for the given IP address (like n.n.n.n) in the description of the given adapter
 1 - found and written to , 0 - not
*/
int findip_addr(pcap_if_t *d, const char* given_name);

/**
 * prints info about adapter
 */
void ifprint(pcap_if_t *, int num);

void processExceptionInSnifferThread(Exception* e) {
	e -> format();
	printf(ERROR_MESSAGE_FORMAT, e -> get_message());	
	delete e;
	raise(SIGINT);
}

class EthDeviceCore {
public:
   static pcap_if_t *alldevs;
};

#define FILE_TO_SEND "file_to_send0.pcap"

SOCKET IPDevice :: s = -1;
bool EthDevice :: is_inited = false;
UInt EthDevice :: defaultSanpLen = 65535;
bool EthDevice :: promisc_mode = true;
pcap_if_t * EthDeviceCore :: alldevs = 0;

UInt TCPDevice :: timeoutInMilliseconds = INFINITE_WAITING;

const string EthDevice :: name("eth");
const string IPDevice  :: name("ip");
const string TCPDevice :: name("tcp");
const string UDPDevice :: name("udp");


/******************************************************
               Class Network
******************************************************/

Network :: Network() {   
   safeTerm = false;
}

void Network :: setDevices(vector<Device*> givenDevices) {
	devices.assign(givenDevices.begin(), givenDevices.end());
}

void Network :: openInterface(const string& device, const MString& name) {

   for (int i = 0; i < devices.size(); i++) {
      if (device == devices[i] -> gettype()) {
			stringstream ss(name);
			MString specName;
			MString uniqueName;
			getline(ss, specName, '#');
			getline(ss, uniqueName, '#');
         Interface* in = devices[i] -> newInterface(specName);
			if (!uniqueName.empty()) {
				in -> setUniqueName(uniqueName);
			}
			else {
				char n[10];
				sprintf(n,"%u",interf.size());
				MString un(n);
				in -> setUniqueName(un);
			}
         in -> setDevice(devices[i]);
         interf.push_back(in);
         return;
      }
   }

   throw new Exception("device with name '%s' is not found", device.c_str());
}

uint Network :: closeInterface(const MString& name) {
   uint n = getInterfaceNumberByName(name, true);
   Interface* i = getInterface(n);
   i -> close();
   delete interf[n];
   interf.erase(interf.begin() + n);
	return n;
}

void Network :: release() {
	//num_open_devs = 0;

   stopAllTrace();
   for (int i = 0; i < interf.size(); i++) {
		interf[i] -> close();
      delete interf[i];
   }
   interf.clear();
}

void Interface :: stopTraceSafely() {

   TerminationConditions cond = getTerminationConditions();

   switch (cond) {
      
      case TC_ANY:
         stopTraceInt();
         break;

      case TC_SAME_THREAD_NOT_REQUEST:
         if (!isThreading()) {
            stopTraceInt();
         }
         else
            stop_thread();

         break;

      case TC_SAME_THREAD_OR_REQUEST:
         if (!isThreading()) {
            stopTraceInt();
            break;
         }

      case TC_REQUEST_THEN_STOP:
      case TC_ONLY_REQUEST:

         if (isThreading()) {
            // TODO: but if it's called from trace-thread
            setRequestToBreakTrace();
            int i=0;
            while (isTracingCurrently() && i++ < 30) {
               mysleep(50);
            }

            if (!isTracingCurrently())
               break;
         }
         
         if (cond == TC_REQUEST_THEN_STOP){
            stopTraceInt();
            break;
         }

         stop_thread();
         
      default: Test();
   }
}

void Network :: stopAllTrace() {

   for (int i = 0; i < numOpenedInterfaces(); i++) {
      interf[i] -> setRequestToBreakTrace();
   }
   if (safeTerm) {      
      for (int i = 0; i < numOpenedInterfaces(); i++) {
         interf[i] -> stopTraceSafely();
      }
   }
   else {
      for (int i = 0; i < numOpenedInterfaces(); i++) {
         interf[i] -> stop_thread();
      }
   }
}

ResultOfTracing Interface :: trace(stresstest_packet_handler packet_handler,void* user_data) {

   startTrace();   
   ResultOfTracing res = traceInt(packet_handler, user_data);
   stopTrace();
   return res;
}

//void Network :: register_device_name(int interface_num, const char* name) {
//
//	int size = strlen(name);
//	check(interface_num < NET_MAX_DEVS);
//	if (size >= MAX_SIZE_DEVICE_NAME) size = MAX_SIZE_DEVICE_NAME - 1;
//	memcpy(device_name[interface_num],name,size);
//	device_name[interface_num][size] = 0;
//}

//const char* Network :: get_device_name(int interface_num) {
//
//	check(interface_num < NET_MAX_DEVS);
//	return device_name[interface_num];
//}

//bool Network :: isThreading(int interface_num) {
//
//	if (interf[interface_num] -> thread != 0) return true;
//	else return false;
//}

//void Network :: set_device_num(int index, int devnum) {
//
//	check(index < num_open_devs);
//
//	for (int i = 0; i < num_open_devs; i++) {
//
//		if (device_num[i] == devnum && devnum != -1 && i != index) {
//
//			throw new Exception("two or more user's device numbers are equal");
//		}
//	}
//
//	device_num[index] = devnum;
//}

int Network :: get_device_num(int index) {

//	check(index < NET_MAX_DEVS);
//	return device_num[index];
   return index;
}

const MString Network :: getNameOfInterface(UInt interfaceNum) {

	check(interfaceNum < interf.size());
	return interf.at(interfaceNum) -> getUniqueName();
//	MString name = interf.at(interfaceNum) -> getName();
//   MString uName = interf.at(interfaceNum) -> getUniqueName();	
//	if (!uName.empty()) {
//		name.append("#");
//		name.append(uName);
//	}
//	return name;
}

UInt Network :: getInterfaceNumberByName(const MString& name, bool failOnNotFound) {

	for (int i = 0; i < interf.size(); i++) {
		MString compoundName = interf[i] -> getName();
		compoundName.append("#");
		compoundName.append(interf[i] -> getUniqueName());
		if (interf[i] -> getName() == name || interf[i] -> getUniqueName() == name || compoundName == name) {
			return i;
		}
	}
	
	if (failOnNotFound) {
		throw new Exception("interface with unique name %s not found : make sure that you have correctly specified unique names (using -d option or somewhat else)", !name);
	}

	return NOT_SUCH_INTERFACE;
}

void Interface :: traceByThread(stresstest_packet_handler tr, void* info) {

   threadInfo.interf = this;
   threadInfo.handler = tr;
   threadInfo.uniqueName= uniqueName;
   threadInfo.user_data = info;

   check(!isThreading());
	#ifdef WIN32
   DWORD thr_id;
	if (NULL == (thread=(HANDLE)CreateThread(0,0,(LPTHREAD_START_ROUTINE)traceThread,&threadInfo,0,&thr_id))) {
	#else
	if (pthread_create(const_cast<pthread_t*>(&thread),0,traceThread,&threadInfo)) {
	#endif

      thread = (HANDLE)0;
		throw new Exception("system : starting thread : %s",strerror(errno));
	}
   #ifndef WIN32
   check(thread != 0);
   #endif
}

void Interface :: stop_thread () {

   //if (i < 3) printf("check3, %i\n",i);
	if (!isThreading()) return;
   
	#ifdef WIN32
	if (!TerminateThread(thread,0)) {

		printf("warning: error while terminating thread\n");
	}
	#else
	pthread_cancel(thread);
	#endif	

   thread = 0;
   stopTrace();
   
}


/******************************************************
               Class EthDevice
******************************************************/

void EthDevice :: setPromisc(bool isPromisc) {

   promisc_mode = isPromisc;
}

void EthInterface :: close() {
	if (core) {
		pcap_close(core -> pcap);
		delete core;
		core = 0;
	}
		// TODO[at] return the stat message back
//   if (getUniqueName() == "0") {
//
//      check(pcap_stats(core -> pcap,&pcap_st) != -1);
////#ifdef WIN32
////			printf("\nTotal number of packets received on first interface = %u (%u)\n", pcap_st.ps_recv, pcap_st.bs_capt);
////#else
//      printf("\nTotal number of packets received at first interface = %u\n", pcap_st.ps_recv);
////#endif
//   }
}

//void EthDevice :: release () {
//
//	if (!is_inited) return;
//
//   Network :: release();
//
//	pcap_freealldevs(alldevs);
//	//close(file_to_send);
//
//}

void EthDevice :: init() {

   if (is_inited) return;

	char errbuf[PCAP_ERRBUF_SIZE];
	int res;

	if ((res=pcap_findalldevs(&(EthDeviceCore :: alldevs), errbuf)) == -1 || !(EthDeviceCore :: alldevs)) {

	  if (res != -1) errbuf[0]=0;

	  #ifdef WIN32
     printf("\nMake sure that WinPcap was installed and run the program with administrator's rights. Usually during installation of WinPcap you can set the flag to load driver on system start-up. It will enable a non-privileged user to use library.\n");
     #else
     printf("\nCan't open device. Try to start by root\n");
     #endif     

	  try {
		throw new Exception(errbuf);
	  }
	  ADD_TO_ERROR_DESCRIPTION("initializing network : error in call to pcap_findalldevs");	       
   }


	/*file_to_send=open(FILE_TO_SEND,O_WRONLY|O_CREAT|O_TRUNC|O_BINARY,S_IWRITE);
   if (file_to_send == -1) {

      sprintf(e.desc,"unable to open file '%s' for write : %s",FILE_TO_SEND,strerror(errno));
      return 1;
   }
   check(write(file_to_send,"\xd4\xc3\xb2\xa1\x02\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\x00\x00\x01\x00\x00\x00",
   24)!=-1);*/

	is_inited = true;	
}



EthInterface :: EthInterface(const MString& devname_t, const EthDevice& device) : Interface(devname_t) {

	pcap_if_t *d;
	pcap_t *fp;
	char errbuf[PCAP_ERRBUF_SIZE];
	int i;

   EthDevice :: init();
	//int devnum = NOT_SUCH_INTERFACE;

//	char* devname = (char*)malloc(strlen(devname_t) + 1);
//	memCheck(devname);
//	strcpy(devname, devname_t);
   MString devname = devname_t;

		// searches symbol # in given name, if finds then cuts the name of interface

//		char* ch = strchr(devname,'#');
//		if (ch) {
//
//			devnum = atoi(ch+1);
//			if (!devnum && (*(ch+1)!='0' || *(ch+2)!=0)) {
//
//				throw new Exception("unknown device : %s - after # expected your device number",devname);
//			}
//			*ch = 0;
//		}
//      else {
//         if (!(devname[0] >= '0' && devname[0] <= '9'))
//            for (int i=0; devname[i]; i++)
//               if (devname[i] >= '0' && devname[i] <= '9' && devname[i+1] == 0) {
//
//                  devnum = atoi(devname+i);
//                  break;
//               }
//      }

		// searching the name of interface amoung ip addresses of adapters	

		i=0;
		for (d = EthDeviceCore :: alldevs; d; d = d->next, i++) {

			if (findip_addr(d,!devname)) {

				// similar ip address found

			  devname = d -> name;	// copies the real name of this adapter
			}
		}
	

	// opening adapter

	//printf("%u\n", defaultSanpLen);

	//if ( (fp = pcap_open(devname, defaultSanpLen, promisc_mode ? PCAP_OPENFLAG_PROMISCUOUS : 0, 20, Null, errbuf) ) == 0) {
	if ( (fp = pcap_open_live(!devname, device.defaultSanpLen, device.promisc_mode, 20, errbuf) ) == 0) {
		
		// fail to open
		// trying to interpret the name of interface as DNS name

		hostent* h = gethostbyname(!devname);
		if (!h) {

			throw new Exception("opening adapter with name '%s' : %s", !devname_t, errbuf);
		}

		if (!(*h).h_addr_list[0]) {

			throw new Exception("opening adapter with name '%s' : %s", !devname_t, errbuf);
		}

		char ipAddr[20];
		sprintf(ipAddr, "%u.%u.%u.%u", 
			*((uchar*)((*h).h_addr_list[0]) + 0),
			*((uchar*)((*h).h_addr_list[0]) + 1),
			*((uchar*)((*h).h_addr_list[0]) + 2),
			*((uchar*)((*h).h_addr_list[0]) + 3)
			);

		// second search the resolved ip address amoung ip addresses of each adapter

		i=0;
		for (d = EthDeviceCore :: alldevs; d; d = d->next, i++) {

			if (findip_addr(d, ipAddr)) {

			  devname = d -> name;	// found
			}
		}

		// second attempt to open adapter

		if ( (fp = pcap_open_live(!devname, device.defaultSanpLen, device.promisc_mode, 20, errbuf) ) == 0)

			// fail again
			throw new Exception("opening adapter with user name '%s' : %s", !devname_t, errbuf);
	} 
      		
//	if (num_open_devs >= NET_MAX_DEVS) {
//
//		throw new Exception("to many opened devices");
//	}

//	devices[numOpenedInterfaces()] = fp;

	//register_device_name(num_open_devs, devname_t);
	
	//num_open_devs++;
//	set_device_num(num_open_devs - 1, devnum);
   
   core = new EthInterfaceCore(this, fp);   
   
//	return num_open_devs;
}


void EthInterface :: setFilter(char* filterString) {

	struct bpf_program fcode;

	if (pcap_compile(core -> pcap, &fcode, filterString, 1, 0) < 0)
   {
        throw new Exception("unable to compile the packet filter. Check the syntax");
        /* Free the device list */
        //pcap_freealldevs(alldevs);
        //return -1;
   }

	if (pcap_setfilter(core -> pcap, &fcode) < 0)
	{
		throw new Exception("error setting the filter");
		/* Free the device list */
		//pcap_freealldevs(alldevs);
		//return -1;
	}
}


void EthInterface :: send(const u_char* buf, int size) {

	int i;	

	if (size < EthInterface :: minimalSizeOfPacket)
		throw new Exception("trying to send too small packet on the channel layer");

	i = pcap_sendpacket(

			core -> pcap,
			buf,
			size
			);

	if (i == -1) {
      throw new Exception("error while sending packet from interface %s", !getName());
   }

   //ind=!ind;
   //ind=true;
   /*if (ind) {

      int u = 0;
      //write(file_to_send,&size,sizeof(u_short));
      write(file_to_send,&u,4);
      write(file_to_send,&u,4);
      u=size;
      write(file_to_send,&u,4);
    *
      write(file_to_send,&u,4);
		check(write(file_to_send,buf,size)!=-1);
	} */

}


void EthDevice :: printAdaptersInfo () {

	int i=0;
	pcap_if_t *d;

   init();
	for(d=EthDeviceCore :: alldevs; d; d=d->next)  ifprint(d,++i);
}

void ifprint(pcap_if_t *d, int num) {

   pcap_addr_t *a;

   /* Name */
   printf("%i. %s\n",num,d->name);

   /* Description */
   if (d->description)
      printf("\tDescription: %s\n",d->description);

   /* Loopback Address*/
   printf("\tLoopback: %s\n",(d->flags & PCAP_IF_LOOPBACK)?"yes":"no");

   /* IP addresses */
   for(a=d->addresses; a; a=a->next) {
      printf("\tAddress Family: #%d\n",a->addr->sa_family);

      switch(a->addr->sa_family)
      {
         case AF_INET:
            printf("\tAddress Family Name: AF_INET\n");
            if (a->addr)
               printf("\tAddress: %s\n",iptos(((struct sockaddr_in *)a->addr)->sin_addr.s_addr));
            if (a->netmask)
               printf("\tNetmask: %s\n",iptos(((struct sockaddr_in *)a->netmask)->sin_addr.s_addr));
            if (a->broadaddr)
               printf("\tBroadcast Address: %s\n",iptos(((struct sockaddr_in *)a->broadaddr)->sin_addr.s_addr));
            if (a->dstaddr)
               printf("\tDestination Address: %s\n",iptos(((struct sockaddr_in *)a->dstaddr)->sin_addr.s_addr));
            break;
         default:
            printf("\tAddress Family Name: Unknown\n");
            break;
      }
   }
   printf("\n");
}


char *iptos(unsigned int in)
{
	static char output[3*4+3+1];
	u_char *p;

	p = (u_char *)&in;
	sprintf(output, "%d.%d.%d.%d", p[0], p[1], p[2], p[3]);
	return output;
}

ResultOfTracing EthInterfaceCore :: start_trace_eth(pcap_handler packet_handler, void* user_data) {

   interf -> startTrace();

   int res;
   pcap_t *fp;

   fp = pcap;
	check(fp != 0);

   res = pcap_loop(fp, -1, packet_handler, (u_char*)user_data);

   interf -> stopTrace();

	if (res == -1) {

		ADDTOLOG1("EthDevice :: start_trace -- res == -1");
		//sprintf(e.desc, "while capturing packets : pcap_loop return %i : %s", res, pcap_geterr(fp));
      return RT_ERROR;
   }

	if (res == -2) {
		//sprintf(e.desc, "internal error (file %s, line %d)",__FILE__,__LINE__);
		ADDTOLOG1("EthDevice :: start_trace -- res == -2");
		return RT_BREAKED;
	}

	ADDTOLOG1("EthDevice :: start_trace -- res == 0");

	return RT_BREAKED;
}

ResultOfTracing EthInterface :: traceInt (stresstest_packet_handler packet_handler, void* user_data) {

	
	struct pcap_packet_handler_info info;	

	info.handler = packet_handler;
	info.user_data = user_data;
	info.uniqueName = getUniqueName();
	info.interf = this;

	ADDTOLOG2("EthDevice :: start_trace, interface %s", !getName());

   return core -> start_trace_eth(pcap_packet_handler, &info);
}

void EthInterface :: stopTraceInt () {
	// if another thread calls this function, it will not work (based on pcap documentation)
	pcap_breakloop(core -> pcap);
}

/******************************************************
               Class IPDevice
******************************************************/

#ifdef WIN32
void IPDevice :: init() {

   if (s != -1) return;

	/*wsalib = LoadLibrary("ws2_32.dll");
	if (!wsalib) {

		sprintf(e.desc, "component ws2_32.dll not found");
		return 1;
	}  */

	//setsockopt_call = (setsockopt_call_type)GetProcAddress(wsalib, "setsockopt");
	//if (!setsockopt_call) Test();

	if (INVALID_SOCKET  == (s = WSASocket (AF_INET, SOCK_RAW, IPPROTO_RAW, NULL,0,
		WSA_FLAG_OVERLAPPED))) {

		throw new Exception("creating socket for RAW IP : %s", winerror(WSAGetLastError()));
	}

	unsigned int use_own_header = 1;

	if ( setsockopt (s, IPPROTO_IP, IP_HDRINCL, (char*)&use_own_header, sizeof(use_own_header))== SOCKET_ERROR)
	{
		throw new Exception("creating RAW IP socket : setting option 'owne header' : %s", winerror(WSAGetLastError()));
	}

	/*int size_of_sndbuf = 65535;
	if ( setsockopt_call (s, SOL_SOCKET, SO_SNDBUF, (char*)&size_of_sndbuf, sizeof(size_of_sndbuf)) == SOCKET_ERROR)
	{
		sprintf(e.desc, "creating socket : setting option 'sndbuf'");
		return 1;
	} */
}
#else
void IPDevice :: init () {

	s = socket(PF_INET, SOCK_RAW, IPPROTO_RAW);
	if (s == -1) {

		throw new Exception("creating RAW IP socket : %s", strerror(errno));		
	}

	int hdrinc = 1;
	if ( setsockopt (s, IPPROTO_IP, IP_HDRINCL, (const char*)&hdrinc, sizeof(hdrinc)) == -1) {
	
		throw new Exception("creating socket : setting option 'IP_HDRINCL': %s", strerror(errno));		
	}

	#if (OS_LINUX == 1)	
	//rs[num_open_devs] = socket(PF_PACKET, SOCK_RAW, htons(0x0800) );
//	if (rs[num_open_devs] == -1) {
//
//		throw new Exception ("creating RAW IP socket : %s", strerror(errno));		
//	}
//	num_open_devs++;
	#endif

// is_inited = true;	
}
#endif

#ifdef WIN32
IPInterface :: IPInterface(const MString& name) : Interface(name) {

   IPDevice :: init();

	hostent* h;
	sockaddr_in target;
   //int devnum = -1;
         
//   char* devname = (char*)malloc(strlen(name)+1);
//	memCheck(devname);
//	strcpy(devname, name);
   MString devname = name;
   SOCKET s;

	try
	{	
//		char* ch = strchr(devname,'#');
//		if (ch) {
//
//			devnum = atoi(ch+1);
//			if (!devnum && (*(ch+1)!='0' || *(ch+2)!=0)) {
//
//				throw new Exception("%s - after # expected your device number",devname);
//			}
//			*ch = 0;
//		}

		h = gethostbyname(!devname);
		if (!h) {

			throw new Exception("name '%s' not resolved",!devname);
		}

		if (!(*h).h_addr_list[0]) {

			throw new Exception("name '%s' not resolved",!devname);
		}

		s = socket(AF_INET, SOCK_RAW, IPPROTO_IP);
		check(s);

		unsigned int use_own_header = 1;

		if ( setsockopt(s, IPPROTO_IP, IP_HDRINCL, (char*)&use_own_header, sizeof(use_own_header))== SOCKET_ERROR)
		{
			throw new Exception("creating socket : setting option 'own header' : %s", winerror(WSAGetLastError()));
		}

		memset(&target,0,sizeof(target));
		memcpy(&target.sin_addr,(*h).h_addr_list[0],4);
		target.sin_family = AF_INET;
		target.sin_port = 0;

		if (SOCKET_ERROR == bind(s,(sockaddr*)&target, sizeof(target))) {

			int er_code = WSAGetLastError();
			if (er_code != WSAEACCES)
				throw new Exception("binding RAW IP socket to address '%s' (code = %u), make sure it's address of your host : %s",!name,er_code,winerror(WSAGetLastError()));
			else
				throw new Exception("creating RAW IP socket : permission denied : you must be ADMINISTRATOR");
		}

		/*use_own_header = 600000;

		if ( setsockopt_call (s, SOL_SOCKET, SO_RCVTIMEO, (char*)&use_own_header, sizeof(use_own_header))== SOCKET_ERROR)
		{
			sprintf(e.desc, "creating socket : setting option 'receive timeout'");
			return -1;
		} */

		#define SIO_RCVALL  0x98000001	
		DWORD optval = 1;
		int i;
		int p = WSAIoctl(s, SIO_RCVALL, &optval, sizeof(optval), 0,0,(ULONG*)&i,0,0);

		if (p == SOCKET_ERROR) {

			throw new Exception("configuring RAW IP socket : %s", winerror(WSAGetLastError()));
		}

		//register_device_name(num_open_devs, !devname);

		//num_open_devs ++;
//		set_device_num(num_open_devs - 1,devnum);

		//return num_open_devs - 1;	
      
	}
	ADD_TO_ERROR_DESCRIPTION2("opening RAW IP interface with user's name '%s'", !name);
   
   
   this -> s = s;
   
}
#else
IPInterface :: IPInterface(const MString& name) : Interface(name) {

	hostent* h;
	sockaddr_in target;
	char hostname[30];

	IPDevice :: init();

	#ifdef OS_LINUX
	throw new Exception("trying to open ip device : for your OS capturing RAW IP - only globaly (you don't need to specify device)");
	#else
	throw new Exception("capturing over RAW IP not supported under your OS");
	#endif   


//	h=gethostbyname(name);
//	if (!h) {
//
//		sprintf(e.desc, "device with name '%s' not opened",name);
//		return -1;
//	}
//
//	if (!(*h).h_addr_list[0]) {
//
//		sprintf(e.desc, "opening device with name '%s'",name);
//		return -1;
//	}



//	memset(&target,0,sizeof(target));
//	memcpy(&target.sin_addr, (*h).h_addr_list[0], 4);
//	target.sin_addr.s_addr = INADDR_ANY;
//	target.sin_family = AF_INET;
//	target.sin_port = 0;
//
//	if (-1 == bind(rs[num_open_devs], (sockaddr*)&target, sizeof(target))) {
//
//		throw new Exception("binding RAW IP socket to address '%s' : %s : make sure it's address of your host",name,strerror(errno));//		
//	}

	//num_open_devs ++;
	//return num_open_devs - 1;
}
#endif


void IPInterface :: close() {
   if (s != -1) {
#ifdef WIN32
         closesocket(s);
#else
         ::close(s);
#endif
         s = -1;
   }
}

#ifdef WIN32
void IPInterface :: send (const u_char* b, int size) {

	sockaddr_in target;

	memset(&target, 0, sizeof(target));
	target.sin_family = AF_INET;
	memcpy(&target.sin_addr.s_addr, b + 16, 4);
	target.sin_port = 0;

	WSABUF wsabuf[1];
	wsabuf[0].len = size;
	wsabuf[0].buf = (char*)b;
	DWORD send;
	int res;
	
	res = WSASendTo (s, wsabuf, 1, &send, 0, (struct sockaddr *)&target, sizeof (target), 0, 0);
	if (send == 0 && size != send) {

		throw new Exception("unknown problem while generating the RAW IP packet : this may be caused by installed firewall");
	}

	if (res == SOCKET_ERROR) {

		int er_code = WSAGetLastError();		

		try {
			switch (er_code) {

				case WSAEACCES:  // Permission denied error code
					throw new Exception("access denied (your must be ADMINISTRATOR)");
					break;
				/*case WSAEHOSTUNREACH:
					sprintf(e.desc + strlen(e.desc), ": NO ROUTE TO HOST");
					break;*/
				case WSAEINTR:
					throw new Exception("operation blocked by OS");
					break;
				default:
					throw new Exception(winerror(WSAGetLastError()));
			}
		}
		ADD_TO_ERROR_DESCRIPTION2("generating RAW IP packet (code = %i)",er_code);		
	}	
}
#else
void IPInterface :: send (const u_char* b, int size) {

	sockaddr_in target;

   #ifdef OS_FREEBSD

   if (size < 20) {

      throw new Exception("generating RAW IP packet : size of packet must be no less then IP header, use standart IP header to generate IP packets");
   }

   int tos = *(b+1);
   check(-1 != setsockopt(s, IPPROTO_IP, IP_TOS, &tos, sizeof(tos)));
   int ttl = *(b+8);
   check(-1 != setsockopt(s, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl)));

   #endif


	memset(&target, 0, sizeof(target));
	target.sin_family = AF_INET;
	memcpy(&target.sin_addr.s_addr, b + 16, 4);
	target.sin_port = 0;

	int res = sendto(s, b, size, 0,(struct sockaddr *)&target, sizeof (target));
	if (res == -1) {

		throw new Exception("generating RAW IP packet : %s", strerror(errno));	
	}
	
}
#endif

ResultOfTracing IPInterface :: traceInt(stresstest_packet_handler packet_handler, void* user_data) {

	struct timeval tv;
	u_char buf[66000];

	#ifdef WIN32
	*(int*)buf = 0;
	*((int*)buf+1) = 0;
	*((int*)buf+2) = 0;
	*(u_short*)(buf+12) = 0x8;
	#endif

	for (;;) {

		#ifdef WIN32
		int res = recv(s, (char*)buf + 14, 66000, 0);
		#else
		int res = recv(s, buf, 1514, 0);
		#endif
		if (res == -1 || res == 0) {

			#ifdef WIN32
			int er_code = WSAGetLastError();

			if (res == -1 && er_code == WSAENOTSOCK) {
				return RT_BREAKED;
			}

			ADDTOLOG4("IPDevice :: start_trace -- receiving by RAW IP socket : %s : code = %i : res =%i",winerror(WSAGetLastError()),er_code,res);

			#else
			int er_code = errno;

			if (er_code == EBADF) {

         	return RT_BREAKED;
			}

			ADDTOLOG3("IPDevice :: start_trace -- receiving by RAW IP socket : %s : res = %i",strerror(er_code),res);

			#endif

			return RT_ERROR;
		}

      if (isRequestToBreakTrace()) {
         return RT_BREAKED;
      }

      tv.tv_sec = 0;
      tv.tv_usec = 0;
		if (packet_handler(buf, res, user_data)) {

			return RT_BREAKED;
		}
	}

	return RT_BREAKED;
}

void IPInterface :: stopTraceInt () {
        
	// close of socket is not good to stop trace
	#ifdef WIN32
	//closesocket(rs[interface_num]);
	#else
	//close(rs[interface_num]);
	#endif
}

//#ifdef WIN32
//void IPDevice :: release() {
//	if (s != -1) closesocket(s);
//   Network :: release();
//}
//#else
//void IPDevice :: release() {
//	if (s != -1) close(s);
//   Network :: release();
//}
//
//#endif

/******************************************************
               Class TCPDevice
******************************************************/

void SocketInterface :: open() {

	const MString name = getName();	
	bool serverMode = false;
   MString name1 = name;	   
	try
	{
		stringstream ss(!name1);
		string side;
		string host;
		string portString;
		getline(ss, side, ':');
		getline(ss, host, ':');
		getline(ss, portString, ':');			
		if (side.empty() || host.empty() || portString.empty()) {
			throw new Exception("incorrect socket interface name (example: client:mail.ru:110 or server:localhost:1000)",!name);
		}

		if (side.compare("server") == 0 || side.compare("s") == 0) {
			serverMode = true;
		}
		else if (side.compare("client") == 0 || side.compare("c") == 0) {
			serverMode = false;
		}
		else {
			throw new Exception("incorrect socket interface name (example: client:mail.ru:110 or server:localhost:1000)",!name);
		}

		hostent* h = gethostbyname(host.c_str());
		if (!h || !(*h).h_addr_list[0]) {
			throw new Exception ("'%s' - unknown host", host.c_str());
		}

		u_short port = atoi(portString.c_str());
		if (port == 0) {
			throw new Exception("'%s' - incorrect socket interface name, expected port number after ':'", !name);
		}

		struct sockaddr_in addr;
		memset(&addr,0,sizeof(addr));
		memcpy(&addr.sin_addr,(*h).h_addr_list[0],4);
		addr.sin_family = AF_INET;
		addr.sin_port = htons(port);

		//register_device_name(num_open_devs, name);

		//num_open_devs ++;
		//return num_open_devs -1;

		this -> s = this -> createSocket(addr, serverMode);
	}
	ADD_TO_ERROR_DESCRIPTION2("opening TCP interface with user's name '%s'", !name);
}


SOCKET UDPInterface :: createSocket(sockaddr_in addr, bool serverMode) {
	SOCKET sock;
	
	#ifdef WIN32
	sock = WSASocket(AF_INET, SOCK_DGRAM, IPPROTO_UDP, 0, 0, 0);
	if (sock == INVALID_SOCKET) {
		throw new Exception("creating socket : %s",winerror(WSAGetLastError()));
	}
	#else
	sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (sock == -1) {
		throw new Exception("creating socket : %s", strerror(errno));      
	}
	#endif

	if (serverMode) {
		if (-1 == bind(sock, (sockaddr*)&addr, sizeof(addr))) {
			throw new Exception("binding : %s", SOCKET_ERROR_MESSAGE);
		}
	}
	else {
		remoteAddr = addr;
	}
	return sock;
}

SOCKET TCPInterface :: createSocket(sockaddr_in addr, bool serverMode) {
	SOCKET sock;
	
	#ifdef WIN32
	sock = WSASocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, 0, 0, 0);
			
	if (sock == INVALID_SOCKET) {
		throw new Exception("creating socket : %s",winerror(WSAGetLastError()));
	}
	#else
	sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (sock == -1) {
		throw new Exception("creating socket : %s", strerror(errno));      
	}
	#endif
	
	if (!serverMode) {

		// CLIENT

		#ifdef WIN32
		if (SOCKET_ERROR == WSAConnect(sock, (sockaddr*)&addr, sizeof(addr), 0, 0, 0, 0)) {
			throw new ConnectionFailedException("attempt to connection has failed : %s", winerror(WSAGetLastError()));      
		}
		#else
		if (-1 == connect(sock, (sockaddr*)&addr, sizeof(addr))) {
			throw new ConnectionFailedException("attempt to connection has failed : %s", strerror(errno));      
		}
		#endif
	}
	else {		

		// SERVER

		if (-1 == bind(sock, (sockaddr*)&addr, sizeof(addr))) {
			throw new Exception("binding : %s", SOCKET_ERROR_MESSAGE);
		}

		if (!Network :: quiet) printf("Waiting for connection...");
		fflush(stdout);

		if (-1 == listen(sock, 1)) {
			throw new Exception("listening on socket : %s", SOCKET_ERROR_MESSAGE);
		}

		fd_set rd_set;
		struct timeval tv;
		int res;

		FD_ZERO(&rd_set);
		FD_SET(sock,&rd_set);

		if (TCPDevice :: timeoutInMilliseconds != INFINITE_WAITING) {

			tv.tv_sec = TCPDevice :: timeoutInMilliseconds / 1000;
			tv.tv_usec = (TCPDevice :: timeoutInMilliseconds % 1000) * 1000;
			res = select(sock + 1, &rd_set, Null, Null, &tv);
		}
		else {

			res = select(sock + 1, &rd_set, Null, Null, Null);
		}

		if (res == -1) {
			throw new ConnectionFailedException("listening on socket : %s", SOCKET_ERROR_MESSAGE);
		}

		if (res == 0) {
			throw new ConnectionTimeoutException("no requests for connection : %s", "timeout has expired");
		}

		SOCKET as;
		socklen_t len = sizeof(addr);
		if (-1 == (as = accept(sock, (sockaddr*)&addr, &len))) {
			throw new Exception("accepting condition : %s", SOCKET_ERROR_MESSAGE);
		}

		if (!Network :: quiet) printf("accepted");

		if (len == sizeof(addr)) {

			char host[101];
			char service[101];
			if (!getnameinfo((sockaddr*)&addr, sizeof(addr), host, 100, service, 100, NI_NUMERICSERV|NI_NUMERICHOST)) {

				if (!Network :: quiet) printf(" from %s : %s", host, service);				
			}
			//else printf("%s", winerror(WSAGetLastError()));				
		}

		if (!Network :: quiet) printf("\n");

#ifdef WIN32
		closesocket(sock);
#else
		::close(sock);
#endif
		sock = as;
	}
	return sock;
}


void SocketInterface :: close() {
   if (s != -1) {
#ifdef WIN32
      closesocket(s);
#else
      ::close(s);
#endif
      s = -1;
   }
}

void UDPInterface :: send(const u_char* buf, int size) {
	
#ifndef WIN32
   if ( size != :: sendto(s, (char*)buf, size, MSG_NOSIGNAL, (sockaddr*)&remoteAddr, sizeof(remoteAddr))) {
#else
	if ( size != :: sendto(s, (char*)buf, size, 0, (sockaddr*)&remoteAddr, sizeof(remoteAddr))) {
#endif	
      throw new SendingOverSocketException("sending data over socket connection : %s", SOCKET_ERROR_MESSAGE);    		
   }
}

void TCPInterface :: send(const u_char* buf, int size) {
	
#ifndef WIN32
   if ( size != :: send(s, (char*)buf, size, MSG_NOSIGNAL)) {
#else
	if ( size != :: send(s, (char*)buf, size, 0)) {
#endif	
      throw new SendingOverSocketException("sending data over socket connection : %s", SOCKET_ERROR_MESSAGE);    		
   }
}

#define TCP_RECV_BUF 1514
ResultOfTracing SocketInterface :: traceInt(stresstest_packet_handler packet_handler, void* user_data) {

   struct timeval tv;
	fd_set rd_set;   
	int offset = getDevice() -> getPositionDataBegins();

   u_char buf[TCP_RECV_BUF];
	   
	memset(buf, 0, offset);
		
	FD_ZERO(&rd_set);

   for (;;) {
		      
		int res;

		// checks is some data ready to read

		FD_SET(s,&rd_set);
		if (TCPDevice :: timeoutInMilliseconds != INFINITE_WAITING) {

			tv.tv_sec = TCPDevice :: timeoutInMilliseconds / 1000;
			tv.tv_usec = (TCPDevice :: timeoutInMilliseconds % 1000) * 1000;
			res = select(s + 1, &rd_set, Null, Null, &tv);
		}
		else {
						
			res = select(s + 1, &rd_set, Null, Null, Null);
		}

		if (!res) {

			// timeout has expired

			return RT_TIMEOUT;
		}

		if (res == -1) {

			// error has occured while checking

			return RT_ERROR;
		}

		// receiving data
		
		#ifdef WIN32
      if ( SOCKET_ERROR == (res = :: recv(s, (char*)buf + offset, TCP_RECV_BUF - offset, 0))) {

         int er_code = WSAGetLastError();

			if (er_code == WSAENOTSOCK) {

				return RT_ERROR;
			}

         ADDTOLOG2("TCP recv error : %s", winerror(WSAGetLastError()));
         return RT_ERROR;
      }
      #else
      if ( -1 == (res = :: recv(s, buf+offset, TCP_RECV_BUF-offset, 0))) {

         int er_code = errno;

			if (er_code == EBADF) {

         	return RT_ERROR;
			}

         ADDTOLOG2("TCP recv error : %s", strerror(er_code));
         return RT_ERROR;
      }
      #endif

      if (res == 0) 
			return RT_ERROR;

      if (isRequestToBreakTrace()) {
         return RT_BREAKED;
      }

      tv.tv_sec = 0;
      tv.tv_usec = 0;
		if (packet_handler(buf, res + offset, user_data)) {

			return RT_BREAKED;
		}      
   }

   return RT_BREAKED;
}

void SocketInterface :: stopTraceInt() {

	
   /*#ifdef WIN32
   closesocket(getTcpInterface(interface_num) -> s);
   #else
	//close(getTcpInterface(interface_num) -> s);
   #endif*/
}


int findip_addr(pcap_if_t *d, const char* given_name) {

   pcap_addr_t *a;
   char ipaddr[20];

   if (!given_name) return 0;

   for(a=d->addresses; a; a=a->next) {

      if (a->addr) {

        if (a->addr->sa_family == AF_INET) {

          strcpy(ipaddr,iptos(((struct sockaddr_in *)a->addr)->sin_addr.s_addr));
          if (strcmp(ipaddr,given_name)==0)
            return 1;
        }
      }
   }
   return 0;
}


#ifdef WIN32
DWORD WINAPI traceThread(LPVOID arg) {
#else
void* traceThread(void *arg) {
#endif
	pcap_packet_handler_info* st = (pcap_packet_handler_info*)arg;

	ADDTOLOG1("traceThread -- starts tracing thread");

	try
	{
		st -> interf -> trace(st -> handler, st -> user_data);
	}
	catch(Exception* e) {
		processExceptionInSnifferThread(e);
	}

	return 0;
}


void pcap_packet_handler (u_char *info, const struct pcap_pkthdr *header,
				  const u_char *data) {

	try {
		
	struct pcap_packet_handler_info *st;
	st = (pcap_packet_handler_info*)info;

	ADDTOLOG3("pcap_packet_handler : got packet : caplen %u : len %u", header -> caplen, header -> len);

	stresstest_packet_handler handler;
	handler = st -> handler;

   EthInterface* ethdev = (EthInterface*)st -> interf;
   
   if (st -> interf -> isRequestToBreakTrace()) {

		ADDTOLOG1("pcap_packet_handler -- request for break");
		ethdev-> stopTraceInt();
      return;
	}

	//if (handler((u_char*)data, header -> ts, header -> caplen, header -> len, st -> user_data)) {
   if (handler((u_char*)data, header -> caplen, st -> user_data)) {

		ADDTOLOG1("pcap_packet_handler -- breaked by handler");
		ethdev -> stopTraceInt();
	}
	
	} catch (Exception* e) {		
		processExceptionInSnifferThread(e);
	}
}


#ifdef WIN32

void init_wsa () {

	WSADATA wsadata;

	if (WSAStartup(MAKEWORD(2, 2), &wsadata)) {

	  throw new Exception("system error : initializing WSA : %s", winerror(WSAGetLastError()));	  
	}	
}
#endif
