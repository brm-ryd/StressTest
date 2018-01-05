#ifndef NETWORK_H
#define NETWORK_H

#include "stresstest.h"
#include "mstring.h"
#include "exceptions.h"
#include "myMutex.h"

#ifdef WIN32
#define _BITTYPES_H
#endif

#ifdef ETHERNET_ACCESS_DETAILS
#include <pcap.h>
#endif


#ifndef WIN32
#define SOCKET_ERROR_MESSAGE (strerror(errno))
#else
#define SOCKET_ERROR_MESSAGE (winerror(WSAGetLastError()))
#endif

#define DT_NOINIT  0
#define DT_ETH     1
#define DT_IP      2
#define DT_TCP     3

#define NOT_SUCH_INTERFACE (0xffffffff)

class Network;
class EthDevice;

#ifdef WIN32

typedef DWORD  (*thread_routing)( LPVOID );

#else

typedef void* (*thread_routing)(void *);
typedef int SOCKET;

#endif // WIN32

/**
 handler of packets of data,
 returns 0 if tracing must be continued, otherwise 1
*/
typedef int (*stresstest_packet_handler)(u_char*, // packet's content
	//struct timeval, // packet's time
	//int caplen,		 // stored part of content (lenght of pkt_data)
	u_int len,			 // size of packet
	void*);			 // additional user info (given while tracing initialization)

#ifdef WIN32
DWORD WINAPI traceThread(LPVOID arg);
#else
void* traceThread(void *arg);
#endif

class Interface;

/**
 * user info that is used with pcap_packet_handler
 */
struct pcap_packet_handler_info {
	
	Interface* interf;
	MString uniqueName;
	stresstest_packet_handler handler;
	void* user_data;
};

enum ResultOfTracing {

	RT_BREAKED,
	RT_ERROR,
	RT_TIMEOUT
};

/**
 * Indicates how tracing may be stopped for a device.
 * Note: a lot depends on by what thread the tracing is being stopped: by trace-thread itself or by another one.
 */
enum TerminationConditions {
   /** method 'stopTraceInt' may be called from any thread
    */
   TC_ANY,
   /** method 'stopTraceInt' will work out only if called by trace-thread
    * if it's not then terminate thread roughly
    */
   TC_SAME_THREAD_NOT_REQUEST,
   /** method 'stopTraceInt' will work out only if called by trace-thread
    * otherwise 'setRequestToBreakTrace' may also work out
    * if not then terminate thread roughly
    */
   TC_SAME_THREAD_OR_REQUEST,
   /** method 'stopTraceInt' will work out called by any thread
    *  but 'setRequestToBreakTrace' should be tried before this (that is more accurately)
    */
   TC_REQUEST_THEN_STOP,
   /** 'setRequestToBreakTrace' may work out
    *  if not then terminate thread roughly
    */
   TC_ONLY_REQUEST   
};






/**
 * binary IP to string n.n.n.n
 */
char *iptos(unsigned int );

/**
 * low-level packets processor,
 * must comply with 'pcap_handler' prototype
 * calls 'stresstest_packet_handler'
 */
void pcap_packet_handler (u_char *, const struct pcap_pkthdr *,
				  const u_char *);

#ifdef WIN32
void init_wsa ();  // to use sockets in windows
#endif

class Device;

/** Opened interface of a device. Base abstract class.
 * Enables to send packets and trace receiving ones.
 * Tracing may be executed in a separate thread.
 */
class Interface {

   friend class Network;

   volatile bool tracingCurrently;
   volatile HANDLE thread;
   MString name;
   volatile bool requestForBreak;
   MString uniqueName;
   Device* device;

protected:
   void setDevice(Device* d) {
      device = d;
   }

public:
   
   pcap_packet_handler_info threadInfo;   

   Interface(const MString& name) : name(name) {
      thread=0;
      requestForBreak=false;
      tracingCurrently=false;
		this->name = name;
      device = 0;
   }

   void startTrace() {
      tracingCurrently = true;
      requestForBreak = false;
//      this -> thread = thread;
   }

   void stopTrace() {
//      thread = 0;
      requestForBreak = false;
      tracingCurrently = false;
   }

   HANDLE getThread() const {
      return thread;
   }

   const MString& getName() const {
      return name;
   }

   const MString& getUniqueName() const {
      return uniqueName;
   }
	
	void setUniqueName(const MString& name) {
		uniqueName = name;
	}

   bool isThreading() {
      return thread != 0;
   }

   bool isTracingCurrently() const {
      return tracingCurrently;
   }

   /**
    *  runs cycle of receiving data, calling given callback for each packet,
	 *  must look at the value returned by callback and stop when needed
    */
	virtual ResultOfTracing traceInt(stresstest_packet_handler packet_handler, void* user_data) = 0;
   /**
    * stops trace (may be called from another thread or from handler of packets), see also method getTerminationConditions
    * @param interface_num
    */
   virtual void stopTraceInt() = 0;

   /**
    ATTENTION: not safe termination,
    the thread must be not active at the moment of the call to this method,
    otherwise the deadlock is possible,
    "activity" may be the call to malloc and others
   */
   void stop_thread ();

   virtual void send (const u_char*,int size) = 0;

   ResultOfTracing trace(stresstest_packet_handler packet_handler,void* user_data);

   /**
    * tries to stop trace thread more safely first, 
    * if not succeeds then kills thread,
    * see TerminationConditions
    */
   void stopTraceSafely();

   /**
    * Sets a flag that tracing should be stopped after next data is received (not immediately, thread will continue to exist).
    * Packet handler must not be called after call to this method.
    * This function is optional, see method getTerminationConditions.
    * To stop the trace-thread safely a latency period is required after setting the flag.
    * It depends on when next data is received
    * @param interfaceNum
    */
   void setRequestToBreakTrace() { requestForBreak = true; }
   bool isRequestToBreakTrace() { return requestForBreak;}

   void traceByThread (stresstest_packet_handler tr, void* info);
   virtual TerminationConditions getTerminationConditions() = 0;
	virtual void close() = 0;
   virtual int getMinimalSizeOfPacket() {return 0;}	
   virtual Device* getDevice() { return device; };
};

class Network {

private:
	
   //int device_num[NET_MAX_DEVS];
	//char device_name[NET_MAX_DEVS][MAX_SIZE_DEVICE_NAME];
   
   //volatile HANDLE interf[NET_MAX_DEVS] -> thread;
   //pcap_packet_handler_info infoForThread[NET_MAX_DEVS];

protected:
   
   bool safeTerm;

   vector<Device*> devices;
   vector<Interface*> interf;

   //volatile bool requestForBreak[NET_MAX_DEVS];
   //volatile bool tracingCurrently[NET_MAX_DEVS];
	
	//int num_open_devs;   

public:
	
	static boolean quiet;
   	
   Network();   
   ~Network() { release(); }
	
	void setDevices(vector<Device*>);
	
//	virtual void init () = 0;
   void openInterface(const string& device, const MString& name);
   uint closeInterface(const MString& name);
   Interface* getInterface(UInt num) {
		// TODO[at] removal of an interface from list causes that other interfaces cannot be get by number
		if (numOpenedInterfaces() == 0) {
			throw new Exception("no opened network interface, use -d option or OPEN command");
		}
		userCheck(num<numOpenedInterfaces());
		return interf.at(num); 
	}
	//virtual int openInterface(const char* name) = 0;
	void release();
	
   /**
    * sets safety of trace termination. Safe termination avoids errors but may be not immediate.
    * see Instance :: stopTraceSafely
    * default is false
    * @param safe
    */
   void setSafeTerm(bool safe) {  safeTerm = safe; } 
   /**
    * stops traces, see setSafeTerm
    */
   void stopAllTrace();   

//	void register_device_name(int interface_num, const char* name);
//	const char* get_device_name(int interface_num);
   int get_device_num(int index);

	int numOpenedInterfaces() { return interf.size(); }
	
	//void set_device_num(int index, int devnum);
   
	/** return device_num */
	//int get_device_num(int index);

	/** returns the index of interface or NOT_SUCH_INTERFACE */
	UInt getInterfaceNumberByName(const MString& name, bool failOnNotFound = false);

	/** returns the unique name of interface or NOT_SUCH_INTERFACE if unique name has not been specified */
	const MString getNameOfInterface(
		UInt interfaceNum	// index of interface
		);
};

/**
 *  Corresponds to a type of access to network (Ethernet, IP, TCP),
 *  just opens new interfaces, then they do the main job
 */
class Device {
public:
   virtual Interface* newInterface(const MString& name) = 0;
   virtual const string& gettype() = 0;
   /**
    * returns position where data starts which will be passed to send method, data before will be ignored while working with device
    */
   virtual UInt getPositionDataBegins() { return 0; }
   virtual UInt getSizeLimit() = 0;
	/**
	 *  true for ethernet access when sniffers work in other threads (means calling traceInt method of interface),
	 *  false for sockets (tcp,udp) when sniffering means reading from socket (everything is buffered),
	 *  when only WAIT commands start sniffering and stop it after receiving what they need
    */
	virtual bool isParallelSniffersAllowed() = 0;
	
};
class EthInterfaceCore;

class EthInterface : public Interface {

   static const int minimalSizeOfPacket = 60;

public:
   EthInterfaceCore* core;
   
   EthInterface(const MString& name, const EthDevice& device);   
   ~EthInterface() { this -> close(); }

   void send(const u_char*, int size);
	ResultOfTracing traceInt(stresstest_packet_handler , void* );
   /** if another thread calls this function, it will not work (based on pcap documentation) */
   void stopTraceInt();
   void setFilter(char* filterString);
   TerminationConditions getTerminationConditions() { return TC_SAME_THREAD_OR_REQUEST; }
   int getMinimalSizeOfPacket() { return minimalSizeOfPacket; }
	void close();   
   #ifdef ETHERNET_ACCESS_DETAILS
   EthInterfaceCore* getCore() { return core; };
   #endif
};

#ifdef ETHERNET_ACCESS_DETAILS
class EthInterfaceCore {

   friend class EthInterface;
   EthInterface* interf;
   pcap_t* pcap;
   
   EthInterfaceCore(EthInterface* in, pcap_t* pcap) {
      interf = in;
      this -> pcap = pcap;
   }
public:
   ResultOfTracing start_trace_eth(pcap_handler packet_handler,void* user_data);
};
#endif

class EthDevice : public Device
{
   friend class EthInterface;
   friend void pcap_packet_handler (u_char *, const struct pcap_pkthdr *,
				  const u_char *);

private:
   
   static bool is_inited;	
	static UInt defaultSanpLen;

private:
	
   static bool promisc_mode;
	
   static void init();
   
public:

   static const string name;

   static void printAdaptersInfo();
   static void setPromisc(bool isPromisc);
	static void setDefaultSanpLen(UInt snapLen) {
		defaultSanpLen = snapLen;
	}

//   EthInterface* getEthInterface(int num) { return static_cast<EthInterface*>(interf[num]); }
   const string& gettype() { return name; }
   Interface* newInterface(const MString& name) { return new EthInterface(name, *this); }
   virtual UInt getSizeLimit() { return 1514; };
	virtual bool isParallelSniffersAllowed() { return true; };
};

class IPInterface : public Interface {
   public:
      SOCKET s;
      IPInterface(const MString& name);      
      ~IPInterface() {
			this -> close();
      }

	void close();
   void send(const u_char*, int size);
	ResultOfTracing traceInt(stresstest_packet_handler packet_handler, void* user_data);
   void stopTraceInt();
   TerminationConditions getTerminationConditions() { return TC_ONLY_REQUEST; }   
   };


class IPDevice : public Device {

	static SOCKET s;

//   IPInterface* getIPInterf(int num) { return static_cast<IPInterface*>(interf[num]); }
   static void init();
   friend class IPInterface;

public:

   static const string name;

	const string& gettype() { return name; }
   Interface* newInterface(const MString& name) { return new IPInterface(name); }
   virtual UInt getSizeLimit() { return 65535 + 14; }
   virtual UInt getPositionDataBegins() { return 14; }
	virtual bool isParallelSniffersAllowed() { return true; };
};

class SocketInterface : public Interface {
	friend class UDPDevice;	
	friend class TCPDevice;	
protected:
	SOCKET s;	
	SocketInterface(const MString& name) : Interface(name) {}
	virtual SOCKET createSocket(sockaddr_in addr, bool serverMode) = 0;
	void open();
	ResultOfTracing traceInt(stresstest_packet_handler packet_handler, void* user_data);
	void stopTraceInt();
   TerminationConditions getTerminationConditions() { return TC_ONLY_REQUEST; }   
	void close();
	~SocketInterface() { this -> close(); }
	
public:
	class SendingOverSocketException : public Exception {
	public:
		SendingOverSocketException(const char* formatString, const char* errorDescription)
			: Exception(formatString, errorDescription) {}
	};
	class ConnectionFailedException : public Exception {
	public:
		ConnectionFailedException(const char* formatString, const char* errorDescription)
			: Exception(formatString, errorDescription) {}
	};
	class ConnectionTimeoutException : public Exception {
	public:
		ConnectionTimeoutException(const char* formatString, const char* errorDescription)
			: Exception(formatString, errorDescription) {}
	};
};


class TCPInterface : public SocketInterface {

protected:	
		
	SOCKET createSocket(sockaddr_in addr, bool serverMode);
	
public:
   
   TCPInterface(const MString& name) : SocketInterface(name) {};      
   virtual void send(const u_char*, int size);	
};

class TCPDevice : public Device {

   friend class TCPInterface;
   
//   TCPInterface* getTcpInterface(int num) { return static_cast<TCPInterface*>(interf[num]); }

public:

   static const string name;
   /** timeout while waiting for connections (in server mode) and new data ('select' function)
    */
	static UInt timeoutInMilliseconds;
   
   
   const string& gettype() { return name; }
   Interface* newInterface(const MString& name) { 
		TCPInterface* in = new TCPInterface(name); 
		in -> open(); 
		return in; 
	}
   virtual UInt getSizeLimit() { return 0x7fffffff; }
   virtual UInt getPositionDataBegins() { return 54; }
	virtual bool isParallelSniffersAllowed() { return false; };
};


class UDPInterface : public SocketInterface {

protected:		
	sockaddr_in remoteAddr;
	SOCKET createSocket(sockaddr_in addr, bool serverMode);
	
public:
   
   UDPInterface(const MString& name) : SocketInterface(name) {  };   
	void send(const u_char* buf, int size);
};

class UDPDevice : public TCPDevice {

   friend class UDPInterface;   

public:

   static const string name;      
   
   const string& gettype() { return UDPDevice :: name; }
   Interface* newInterface(const MString& name) { 
		UDPInterface* in = new UDPInterface(name); 
		in -> open(); 
		return in;
	}   
   virtual UInt getPositionDataBegins() { return 42; }
	
};

#endif // NETWORK_H
