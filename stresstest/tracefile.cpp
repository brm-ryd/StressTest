#include "stdafx.h"
#include "tracefile.h"

#include "convimit.h"


TraceFile :: TraceFile()
{
   byte_order = 0;
	memset(&start_time, 0, sizeof(start_time));

	posLastFoundPacket = 0;
	numLastFoundPacket = 0;
}

TraceFile :: ~TraceFile() {}


u_char* TraceFile :: getStartPos() throw(Exception*) {

	if (!buffer) {

		throw new Exception("you have tried to work with trace file but no file opened");
	}

	try
	{

	// processing

   if (*(u_int*)buffer == 0xd4c3b2a1) {

      byte_order = 1;
      throw new Exception("program doesn't support file's byte order");
   }
   else if (*(u_int*)buffer != 0xa1b2c3d4) {

         throw new Exception("file doesn't have libpcap format (no number)");
      }

   if (getSize() <= 24) {

		return NO_MORE_PACKETS;
   }

   start_time.sec = *(u_int*)(buffer+24);
   start_time.usec = *(u_int*)(buffer+28);

	} //try

	ADD_TO_ERROR_DESCRIPTION("working on content opened trace file");

   return buffer;
}

u_char* TraceFile :: getNextPacket(u_char* cur, u_int* sizeOfFoundPacket, TimeStamp* timeOfFoundPacket) {

   check(cur);
	check(sizeOfFoundPacket);

	if (cur == NO_MORE_PACKETS) return NO_MORE_PACKETS;

   if (cur == buffer) {

      cur = buffer + 24;

   } else {

      cur -= 16;

      u_int pac_size = *(u_int*)(cur + 8); /* packet header:
																timestamp = 8 bytes,
																captured bytes = 4 bytes,
																actual stored bytes = 4 bytes
														 */

      cur += 16 + pac_size;

      if (cur >= buffer + getSize()) {

         return NO_MORE_PACKETS;
      }
   }


   if (timeOfFoundPacket) {  // timestamp: sec - 4 bytes, usec - 4 bytes;

      timeOfFoundPacket -> sec = *(u_int*)cur;
      timeOfFoundPacket -> usec = *(u_int*)(cur + 4);

      GetTimeDif(timeOfFoundPacket, &start_time);
   }

	userCheck(sizeOfFoundPacket);
   *sizeOfFoundPacket = *(u_int*)(cur + 8);

   return cur + 16;
}


void TraceFile :: deletePacket(uint numberOfPacketToDelete, TimeStamp* timeOfPacket) throw(Exception*) {

	uint sizePacket;
	uchar* pacBuf = getPacketByNumber(numberOfPacketToDelete, &sizePacket, 0);

	numLastFoundPacket = 0;

	if (timeOfPacket) {

		timeOfPacket -> sec = *(UInt*)(pacBuf - 16);
		timeOfPacket -> usec = *(UInt*)(pacBuf - 12);
	}

	uint sizeOfBlock = getSize() - (uint)((pacBuf - SIZE_INFO_FOR_PACKET) - buffer);
	uchar* c = (uchar*)malloc(sizeOfBlock);
	memCheck(c);
	memcpy(c, pacBuf - SIZE_INFO_FOR_PACKET, sizeOfBlock);

	memcpy(
		pacBuf - SIZE_INFO_FOR_PACKET, c + sizePacket + SIZE_INFO_FOR_PACKET,
		sizeOfBlock - sizePacket - SIZE_INFO_FOR_PACKET);

	setSize(currentSize - (sizePacket + SIZE_INFO_FOR_PACKET) );

	::free(c);
}


void TraceFile :: insertPacket(uint numberOfPacketToOffset, const UChar* contentOfPacket, uint sizePacket, bool useExistingTime, const TimeStamp* time) throw(Exception*) {

	uint sizeExistingPacket;

	checkAllocation(getSize() + sizePacket + SIZE_INFO_FOR_PACKET);

	UChar* pacBuf;

	try
	{
		pacBuf = getPacketByNumber(numberOfPacketToOffset, &sizeExistingPacket, 0);
	}
	catch (Exception* e) {

		delete e;
		pacBuf = buffer + currentSize + SIZE_INFO_FOR_PACKET;
		*(u_int*)(pacBuf - 16) = 0;
		*(u_int*)(pacBuf - 12) = 0;
	}

	numLastFoundPacket = 0;

	uint sizeOfBlock = currentSize - ((pacBuf - SIZE_INFO_FOR_PACKET) - buffer);
	uchar* c = (uchar*)malloc(sizeOfBlock);
	userCheck(c);

	memcpy(c, pacBuf - SIZE_INFO_FOR_PACKET, sizeOfBlock);

	if (!useExistingTime) {

		// copies the time of packet

		check(time);

		*(u_int*)(pacBuf - 16) = time -> sec;
		*(u_int*)(pacBuf - 12) = time -> usec;
	}

	// copies the sizes

	*(uint*)(pacBuf - 8) = sizePacket;
	*(uint*)(pacBuf - 4) = sizePacket;

	// copy content packet

	memcpy(pacBuf, contentOfPacket, sizePacket);

	// copy previous stored block

	memcpy(pacBuf + sizePacket, c, sizeOfBlock);

	setSize(currentSize + (int)sizePacket + (int)SIZE_INFO_FOR_PACKET);

	::free(c);
}

UInt TraceFile :: getTotalNumberOfPackets() {

	check(isOpened());

	uint n = 0;
	UInt size;
	uchar* curPac = getFirstPacket(&size);

	while (curPac != NO_MORE_PACKETS) {

		n++;
		curPac = getNextPacket(curPac, &size);
	}

	return n;
}


uchar* TraceFile :: getPacketByNumber(uint numberOfPacket, uint* sizeOfFoundPacket, TimeStamp* timeOfFoundPacket) throw(Exception*) {

	static UInt sizeLastFoundPacket = 0;
	static TimeStamp timeLastFoundPacket;
	static TimeStamp time;

	uint n = 1;
	uchar* curPac = getFirstPacket(sizeOfFoundPacket, &time);

	if (numLastFoundPacket != 0 && numberOfPacket >= numLastFoundPacket) {

		curPac = posLastFoundPacket;
		n = numLastFoundPacket;
		time = timeLastFoundPacket;
		*sizeOfFoundPacket = sizeLastFoundPacket;
	}

	while (curPac != NO_MORE_PACKETS) {

		if (n == numberOfPacket) {

			numLastFoundPacket = n;
			posLastFoundPacket = curPac;
			timeLastFoundPacket = time;
			sizeLastFoundPacket = *sizeOfFoundPacket;

			if (timeOfFoundPacket) *timeOfFoundPacket = time;

			return curPac;
		}
		n++;
		curPac = getNextPacket(curPac, sizeOfFoundPacket, &time);
	}

	throw new Exception("this packet number (%u) doesn't exist", numberOfPacket);
}

u_char* TraceFile :: gotoNextEndPoint(u_char* cur, EndPoint* ep, u_int* numEPs, u_int* psize, u_int* pnum, TimeStamp* time) {

   for (;;) {

      (*pnum)++;
      if ((cur = getNextPacket(cur,psize,time)) == 0) return 0;

      for (u_int i=0; i < *numEPs; i++)
         if (ep[i].f -> isContent(cur,*psize) == ICR_OK) {

            *numEPs = i;
            return cur;
         }
   }
}

int TraceFile :: findAllFields(CommonField** eps, uint numEPs, CommonField* mask, CommonField* mask1,
    u_int** pac_nums, u_int* npac_nums) {

   u_int pac_size;
   u_int i,j;
   int pac_num = 0;

   check(buffer); // file was not opened

   if (pac_nums) {

		if (!npac_nums) Test();
		*npac_nums = 0;
		*pac_nums = 0;
   }

   u_char* cur = getStartPos();

   for (i = 0; i < numEPs; ) {

		// next packet
      cur = getNextPacket(cur, &pac_size);
      if (!cur) break;

      pac_num ++;

		// check by filter
      if (mask && (mask -> isContent(cur,pac_size)) != ICR_OK) continue;
      if (mask1 && (mask1 -> isContent(cur,pac_size)) != ICR_OK) continue;

		// try init end point by the packet
      if (eps[i] -> setByPacket(cur, pac_size) == ICR_NOT_SUCH_FIELD) continue;

		// add packet number into array

      if (pac_nums) {

         AddVal((void**)pac_nums,npac_nums,sizeof(**pac_nums));
         (*pac_nums)[*npac_nums-1] = pac_num;
      }

		// searching equal end point

      for (j = 0; j < i; j++) {

         if (*eps[i] == *eps[j]) break;
      }

      if (j != i) {
			// found an equal one
         continue;
      }

		// new end point found
      i++;
   }

   return i;
}
