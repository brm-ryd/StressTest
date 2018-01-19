/** still not working - wrong implementation **/
#ifndef _TRACEFILE_H_
#define _TRACEFILE_H_

#include "stresstest.h"
#include "stresstest_functs.h"
//#include "packet buffering.h"
#include "fileWorker.h"
#include "exceptions.h"

#define NO_MORE_PACKETS 0

#ifdef WIN32
struct TimeStamp {

   u_int sec;
   u_int usec;

	void operator=(const int number) { sec = number; usec = number; }
	int operator-(const TimeStamp& t2) const;
};
#else
struct TimeStamp {

	time_t sec;
	suseconds_t usec;

	void operator=(const int number) { sec = number; usec = number; }
	int operator-(const TimeStamp& t2) const;
};
#endif


/**
	Works with trace files complied with libpcap format
*/
class TraceFile : public FileWorker
{

private:

	static const uint SIZE_INFO_FOR_PACKET = 16;
	static const uint SIZE_OF_HEADER = 24;

 private:

   bool byte_order;
   TimeStamp start_time;

	/** following two variables are used for fast search packet by its number (method getPacketByNumber)*/
	UInt numLastFoundPacket;
	UChar* posLastFoundPacket;

protected:

public:


public:

   TraceFile();
   ~TraceFile();

	bool isOpened() {

		if (buffer) return true;
		else return false;
	}

	void load(const char* filename) throw(Exception*) {

		numLastFoundPacket = 0;
		FileWorker :: load(filename);
	}

	/** always returns pointer to packet buffer*/
	uchar* getPacketByNumber(
		uint numberOfPacket, // 1-based number of packet in file
		uint* sizeOfFoundPacket, // [out]
		TimeStamp* timeOfFoundPacket // [out] may be 0
		) throw(Exception*);

	/** delete packet*/
	void deletePacket(
		uint numberOfPacketToDelete,	// 1-based number of packet in file
		TimeStamp* timeOfPacket	= Null// if not Null, retrieves the time of deleted packet
		) throw(Exception*);

	/** insert given packet to the given position in file, offsetting all other packets*/
	void insertPacket(
		uint numberOfPacketToOffset, // this packet and all next will be offset
		const UChar* contentOfPacket, // content of inserted packet
		uint sizePacket,			// size of content
		bool useExistingTime = true,	// true - sets the time equal to the time of offset packet
		const TimeStamp* time = 0	// may be null only if useExistingTime = true
		) throw(Exception*);

	void replacePacket(UInt numPac, const UChar* contentOfPacket, UInt sizePac) {

		TimeStamp timeOfPacket;

		deletePacket(numPac, &timeOfPacket);
		insertPacket(numPac, contentOfPacket, sizePac, false, &timeOfPacket);
	}

	/** returns the pointer which may only be given to findNext or gotoNextEndPoint, NOT FOR OTHER USE*/
   u_char* getStartPos() throw(Exception*);

	/**
	 returns the pointer to the first packet's buffer or NO_MORE_PACKETS,
	 returned pointer may be given to findNext or gotoNextEndPoint
	*/
	uchar* getFirstPacket(
		uint* sizeOfFoundPacket, // [out]
		TimeStamp* timeOfFoundPacket = Null// [out] may be 0
		) throw(Exception*) {

		return getNextPacket(getStartPos(), sizeOfFoundPacket, timeOfFoundPacket);
	}

	/**
    moves to next packet in file, given pointer must point to current packet,
	 returns pointer to packet's buffer or NO_MORE_PACKETS
   */
   u_char* getNextPacket(u_char* cur,			// [in] pointer to current packet in this file
						  u_int* sizeOfFoundPacket,	// [out] size of new packet
						  TimeStamp* timeOfFoundPacket = 0  // [out] time of new packet
						  );

	/** returns the pointer to the next packet from file belonging to any EndPoint from given array*/
   u_char* gotoNextEndPoint(
							 u_char* cur,	// [in] pointer to current packet in this file
							 EndPoint* ep,			// array of EndPoints
							 u_int*	  numEPs,	/* [in] number of items in array 'ep',
															[out] EndPoint for found packet as index in array 'ep'
															*/
							 u_int*    psize,		// [out] size of new packet
							 u_int*    pnum,		// [in,out] packet's number in trace file (some value will be simply added to 'pnum' after function call)
							 TimeStamp* time = 0);	//  [out] time of new packet



	UInt getTotalNumberOfPackets();

   /**
    * @param eps array
    * @param numEPs size of the array
    * @param mask only those packets are proccessed for which call to CommonField :: isContent returns true
    * @param mask1 only those packets are proccessed for which call to CommonField :: isContent returns true
    * @param pac_nums [out] numbers of packets by which end points were initialized
    * @param npac_nums size of pac_numns
    * @return number of initialized end points
    */
   int findAllFields(CommonField** eps,
							uint numEPs,
							CommonField* mask = 0,
							CommonField* mask1 = 0,
							u_int** pac_nums = 0,
							u_int* npac_nums = 0);
};


#endif // _TRACEFILE_H_
