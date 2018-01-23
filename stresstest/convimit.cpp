#include "stdafx.h"
#include "convimit.h"
#include "mutex.h"
#include "reqandstat.h"
//---------------------------------------------------------------------------

// **********************************************************
// ***************  class  AdaptiveRepmaker  ****************
// **********************************************************


void AdaptiveRepmaker :: operator=(const AdaptiveRepmaker& sourceObject) {

	repMakers = sourceObject.repMakers;

	rec = sourceObject.rec;
	gen = sourceObject.gen;

//	for (int i = 0; i < numConstraints; i++) {
//
//		if (filters[i]) delete filters[i];
//		if (sourceObject.filters[i]) filters[i] = sourceObject.filters[i] -> copy();
//		else filters[i] = Null;
//	}
	filters = sourceObject.filters;

	if (packetsNumbers) delete packetsNumbers;
	if (sourceObject.packetsNumbers && sourceObject.numPacketsNumbers) {

		packetsNumbers = new int[sourceObject.numPacketsNumbers];
		numPacketsNumbers = sourceObject.numPacketsNumbers;
	}
	else {

		packetsNumbers = Null;
		numPacketsNumbers = 0;
	}

	_isSet = sourceObject._isSet;
}


void AdaptiveRepmaker :: init(vector<FieldReplace>* repMakers, UInt rm, UInt gm, int* packetsNumbers, int numPacketsNumbers) {

   userCheck(!(*repMakers)[rm].rm.isActive());
   userCheck(!(*repMakers)[gm].rm.isActive());

	this -> repMakers = repMakers;
   rec = rm;
   gen = gm;
   this -> packetsNumbers = packetsNumbers;
   this -> numPacketsNumbers = numPacketsNumbers;



//   filters[0] = 0;
//   filters[1] = 0;
//   filters[2] = 0;
}

bool AdaptiveRepmaker :: isMatchFilters(const u_char* buf, uint size) const {

	for (vector<CommonField>::const_iterator it = filters.begin(); it!=filters.end(); ++it) {
		if (it -> isContent(buf,size) != ICR_OK) {
			ADDTOLOG1("AdaptiveRepmaker :: applyCieve -- filter not matchs");
			return false;
		}
	}

	return true;
}

void AdaptiveRepmaker :: applyCieve(const u_char* baseBuffer, u_char* modifiedBuffer, UInt size, UInt numCurrentPacket) const {

   int i;

	ADDTOLOG1("AdaptiveRepmaker :: applyCieve -- start");

   if (packetsNumbers) {

      for (i = 0; i < numPacketsNumbers; i++)  if (numCurrentPacket == packetsNumbers[i]) break;
      if (i == numPacketsNumbers) return;
   }

   if (!isMatchFilters(baseBuffer,size)) return;

	if (((*repMakers)[rec].rm.getTargetVal() -> setByPacket(baseBuffer,size)) == ICR_NOT_SUCH_FIELD) {

		ADDTOLOG1("AdaptiveRepmaker :: applyCieve -- not such field");
      return;
	}

	ADDTOLOG1("AdaptiveRepmaker :: applyCieve -- applied");

   (*repMakers)[rec].rm.getTargetVal() -> fillPacket(modifiedBuffer, size);
}

u_int AdaptiveRepmaker :: processPacket(u_char* buf, u_int size, u_int group_mask, int numCurrentPacket, int group) {

   int i;

	ADDTOLOG1("AdaptiveRepmaker :: setByPacket -- start");

	if (_isSet) {

		ADDTOLOG1("AdaptiveRepmaker :: setByPacket -- already set");
		return group_mask;
	}

   if (packetsNumbers) {

      for (i = 0; i < numPacketsNumbers; i++)  if (numCurrentPacket == packetsNumbers[i]) break;
      if (i == numPacketsNumbers) return group_mask;
   }

	if (group_mask & (1 << group)) {

		ADDTOLOG1("AdaptiveRepmaker :: setByPacket -- group is already set");
		return group_mask;
	}

	if (!isMatchFilters(buf,size)) return group_mask;

	if ((*repMakers)[rec].rm.getTargetVal() -> setByPacket(buf, size) == ICR_NOT_SUCH_FIELD) return group_mask;
	(*repMakers)[gen].rm.getTargetVal() -> setValue((*repMakers)[rec].rm.getTargetVal() -> getValue());

	(*repMakers)[rec].rm.setActive(true);
	(*repMakers)[gen].rm.setActive(true);

	ADDTOLOG1("AdaptiveRepmaker :: setByPacket -- is set");

	_isSet = true;
	group_mask |= 1 << group;
   return group_mask;
}


// **********************************************************
// ************* Common functions  **************************
// **********************************************************

void GetTimeDif(TimeStamp* t1, TimeStamp* t2) {

   u_int s = t1->sec - t2->sec;
   int u = t1->usec - t2->usec;

   if (u<0) {

      u = 1000000 + u;
      s--;
   }
   t1->sec = s;
   t1->usec = u;
}


int TimeStamp :: operator-(const TimeStamp& t2) const {

   int sec = this -> sec - t2.sec;
   int usec = this -> usec - t2.usec;

   if (sec > 1000) sec = 10;
   if (sec < -1000) sec = -10;

   return usec + sec * 1000000;
}

int generator(ConvImit** interactions, u_int nconv, TraceFile* file, Network* dev) {

   return 0;
}

void AddVal(void** p, u_int* ar_size, u_int item_size, int step_of_size) {

   if (*p) {

      (*ar_size) += step_of_size;
      *p = realloc(*p,(*ar_size) * item_size);
      memCheck(*p);
   }
   else {

      *ar_size = step_of_size;
      *p = malloc((*ar_size) * item_size);
      memCheck(*p);
   }
}

void AddEndPoint(EndPoint** array, int* ar_size, CommonField* ep, int dev) {

   AddVal((void**)array, (u_int*)ar_size, sizeof(EndPoint));

   (*array + *ar_size - 1) -> f = (new CommonField(*ep));
   (*array + *ar_size - 1) -> interfaceNum = dev;
}

void cieve_crc (u_char* pac, u_char* buf, int size) {

   if (size>=34) {

      if (*(u_short*)(pac+12) == 0x8) {

         buf[14+10] = pac[14+10];
         buf[14+11] = pac[14+11];

         if (size >= 34+20 && *(pac+14+9) == 0x6) {

            buf[34+16] = pac[34+16];
            buf[34+17] = pac[34+17];
         }

         if (size >= 34+8 && *(pac+14+9) == 0x11) {

            buf[34+6] = pac[34+6];
            buf[34+7] = pac[34+7];
         }

         if (size >= 34+8 && *(pac+14+9) == 0x1) {

            buf[34+2] = pac[34+2];
            buf[34+3] = pac[34+3];
         }
      }
   }
   return;
}

void fixe_bag (u_char* pac, u_char* buf, int size) {

   if (size > 14 && *(u_short*)(pac+12) == 0x8) {

      u_short len = htons(*(u_short*)(pac+16));

      //printf("Hollow\n");
      if (14+len < size)
         buf[14+len] = pac[14+len];
   }
}

/************************************************************
/******************** Class ConvImit ************************
/************************************************************
/***********************************************************/


ConvImit :: ConvImit() {

	conv_serial = -1;

	device = 0;
	file = 0;

   isWaitInfinity = false;

   //repmakers = 0;
 //  numRepmakers = 0;

   //arepmakers = 0;
   //numArepmakers = 0;

  // cieves = 0;
  // numCieves = 0;

	sender.receiver = &receiver;
	receiver.sender = &sender;

	//sender.setReferenceToExternalReplaces(&repmakers);
	//receiver.setReferenceToExternalReplaces(&repmakers);

	//receiver.setReferenceToExternalARepMakers(&arepmakers);
}

ConvImit :: ~ConvImit() {

}


int ConvImit :: init(TraceFile* tfile) {

   file = tfile;
	sender.setFile(file);
	receiver.setFile(file);

   return 0;
}


/************************************************************
/*************** Class InteractionControl *******************
/************************************************************
/***********************************************************/


InteractionControl :: InteractionControl() {

	startPacket = 0;

	status = statusUndefined;

	eps = 0;									numEPs = 0;
	numCurrentEP = 0;						numCurrentPacket = 0;
	pointerCurrentPacket = 0;			sizeCurrentPacket = 0;
	numInterfaceForCurrentPacket = 0;

	replaces = 0;
//	numReplaces = 0;

	file = 0;

	bufferCurrentPacket = new u_char[SIZE_PACKET_BUFFER];
	memCheck(bufferCurrentPacket);
}


void InteractionControl :: setFile(TraceFile* externFile) {

	file = externFile;
	reset();
}


void InteractionControl :: reset() {

	if (file) {

		pointerCurrentPacket = file -> getStartPos();
		numCurrentPacket = 0;

		gotoNextPacket();

		while (startPacket && numCurrentPacket < startPacket && pointerCurrentPacket)
			gotoNextPacket();
	}
}


void InteractionControl :: gotoNextPacket() {

   u_int eps_num = numEPs;

   pointerCurrentPacket =
		file -> gotoNextEndPoint(pointerCurrentPacket, eps, &eps_num, &sizeCurrentPacket, &numCurrentPacket, &timeCurrentPacket);

   if (!pointerCurrentPacket) return;

   check(sizeCurrentPacket);

   numInterfaceForCurrentPacket = eps[eps_num].interfaceNum;
}

void InteractionControl :: readyBuffer(u_char* baseBuf, u_int sizeBaseBuf) {

	ADDTOLOG1("InteractionControl :: readyBuffer -- start");

	memcpy(bufferCurrentPacket, baseBuf, sizeBaseBuf);

	if (replaces)

		for (vector<FieldReplace> :: iterator i = (*replaces).begin(); i != (*replaces).end(); i++) {

			if (
					(i -> status & RM_REC) && (status == receiver)
					|| (i -> status & RM_GEN) && (status == sender)
				)

				i -> rm.replace(baseBuf, bufferCurrentPacket, sizeBaseBuf);

			else
				ADDTOLOG1("InteractionControl :: readyBuffer -- incorrect type");
		}
}

ReceivingControl :: ReceivingControl() {

	status = receiver;

	pointerLastReceivedPacket = 0;

	//adaptedBufferExpectedPacket = new u_char[InteractionControl :: SIZE_PACKET_BUFFER];
	//memCheck(adaptedBufferExpectedPacket);

	arepmakers = 0;
//	numArepmakers = 0;

	isFirstPacketExpected = true;
	working = false;

	device = 0;
	sender = 0;
}

ReceivingControl :: ~ReceivingControl() {

	//if (adaptedBufferExpectedPacket)
	//	delete[] adaptedBufferExpectedPacket;
}

void ReceivingControl :: readyBuffer(u_char* baseBuf, u_int sizeBaseBuf) {

	InteractionControl :: readyBuffer(baseBuf, sizeBaseBuf);

	//memcpy((void*)adaptedBufferExpectedPacket,(void*)baseBuf, sizeBaseBuf);
}

void ReceivingControl :: gotoNextPacket() {

	pointerLastReceivedPacket = pointerCurrentPacket;

	InteractionControl :: gotoNextPacket();

	isFirstPacketExpected = false;

	if (!pointerCurrentPacket) {

		working = false;
		return;
	}

	readyBuffer(pointerCurrentPacket, sizeCurrentPacket);
}
bool ReceivingControl :: newPacketReceived(u_char* bufferReceivedPacket, u_int sizeReceivedPacket, int numReceivingInterface) {

   u_int comparedSize = (sizeReceivedPacket < sizeCurrentPacket) ? sizeReceivedPacket : sizeCurrentPacket;

	userCheck(sender);

#ifdef SSPT2_BUG

	if (sizeReceivedPacket > 14 && *(UShort*)(bufferReceivedPacket+12) == 0x8) {

		if (sizeReceivedPacket > 34) {

			UShort len = htons(*(UShort*)(bufferReceivedPacket+16));

			if (len + 14 < comparedSize) comparedSize = len + 14;
		}
	}

#endif

	// check if packet has actually been generated (the received one may be an accidental one not related to this test)
   if (numCurrentPacket >= sender -> getNumCurrentPacket()) return 0;
   if (numInterfaceForCurrentPacket != numReceivingInterface) return 0;

   if (!pointerCurrentPacket)
		return false;

	ADDTOLOG3("ReceivingControl :: newPacketReceived -- start, bufferReceivedPacket = \n%s\nbufferCurrentPacket = \n%s",
		getStringOfDump(bufferReceivedPacket, comparedSize),getStringOfDump1(bufferCurrentPacket, comparedSize));
	/*printf("ReceivingControl :: newPacketReceived -- start, bufferReceivedPacket = \n%s\nbufferCurrentPacket = \n%s",
		getStringOfDump(bufferReceivedPacket, comparedSize),getStringOfDump1(bufferCurrentPacket, comparedSize));*/

	for (vector<CommonField> :: iterator i = (*cieves).begin(); i != (*cieves).end(); i++) {

		CommonField* f = new CommonField(*(i));

		f -> setByPacket(bufferReceivedPacket, comparedSize);
		f -> fillPacket(bufferCurrentPacket, comparedSize);

		ADDTOLOG2("ReceivingControl :: newPacketReceived -- after appling cieve, packet = \n%s",
				getStringOfDump(bufferCurrentPacket,comparedSize));
		/*printf("ReceivingControl :: newPacketReceived -- after appling cieve, packet = \n%s",
				getStringOfDump(bufferCurrentPacket,comparedSize));*/

		delete f;
	}

	// correct received packet by adaptive test workers

	for (vector<FieldAdaptiveReplace> :: iterator i = (*arepmakers).begin(); i != (*arepmakers).end(); i++)
		if (!i -> a.isInitialized()) {

         i -> a.applyCieve(bufferReceivedPacket, bufferCurrentPacket, comparedSize, numCurrentPacket);
			ADDTOLOG2("ReceivingControl :: newPacketReceived -- after appling AdaptiveRepmaker, packet = \n%s",
				getStringOfDump(bufferCurrentPacket,comparedSize));
			/*printf("ReceivingControl :: newPacketReceived -- after appling AdaptiveRepmaker, packet = \n%s",
				getStringOfDump(bufferCurrentPacket,comparedSize));*/
		}

   //Cieve(bufferReceivedPacket, comparedSize);
	ADDTOLOG3("ReceivingControl :: newPacketReceived -- comparing, bufferReceivedPacket = \n%s\nbufferCurrentPacket = \n%s",
		getStringOfDump(bufferReceivedPacket, comparedSize),
		getStringOfDump1(bufferCurrentPacket, comparedSize)
		);

	// final compare

   if (memcmp(bufferCurrentPacket, bufferReceivedPacket, comparedSize)) {

		// not hit

      return false;
   }

	ADDTOLOG1("ReceivingControl :: newPacketReceived -- received");

	// THE EXPECTED PACKET IS RECEIVED

#ifdef DEBUG_CONVTEST
	printf("received packet %i (interface %i)\n", numCurrentPacket, numReceivingInterface);
#endif

	printf(".");
	fflush(stdout);

   u_int group_mask = 0;  // !

	// pass the packet to adaptive test workers
	for (vector<FieldAdaptiveReplace> :: iterator i = arepmakers -> begin(); i != arepmakers -> end(); i++)
      if (!i -> a.isInitialized())
			group_mask = i -> a.processPacket(bufferReceivedPacket,comparedSize,group_mask,
																		 numCurrentPacket, i -> group);

   gotoNextPacket();

   return true;
}


void ReceivingControl :: reset() {

	pointerLastReceivedPacket = file -> getStartPos();

	working = true;
	InteractionControl :: reset();
	isFirstPacketExpected = true;
}

//void ReceivingControl :: cieve(u_char* baseBuf, u_int sizeBaseBuf) {
//
//   for (int i = 0; i < numCieves; i++) {
//
//      if (cieves[i] -> setByPacket(baseBuf, sizeBaseBuf) == ICR_NOT_SUCH_FIELD) continue;
//      cieves[i] -> fillPacket(bufferCurrentPacket, sizeCurrentPacket);
//   }
//}

SendingControl :: SendingControl() {

	stopPacket = 0;
	startPacket = 0;

	status = sender;

	timeOfLastGeneration = 0;
	timePacketToGenerate = 0;
	timeOfFirstGeneration = 0;

	device = 0;
	timed_mode = false;
	isWaitInfinity = false;

	receiver = 0;

	timeout = defaultTimeout;
	maxNumOfRetransmitions = 1;
	numberOfRetransmitionsOfCurrentPacket = 0;

	reset();
}
//void SendingControl :: readyBuffer(u_char* baseBuf, u_int sizeBaseBuf) {
//
//	memcpy((void*)bufferCurrentPacket, baseBuf, sizeBaseBuf);
//}
int SendingControl :: generate(const TimeStamp* currentTime) {

   int dif;

	userCheck(device);
	userCheck(receiver);

	ADDTOLOG3("SendingControl :: generate -- start, time %u.%u", currentTime -> sec, currentTime -> usec);

   for (;;) {


      /*if (stop_pos && numCurrentPacket >= stop_pos) {

         pointerCurrentPacket = 0;
			numCurrentPacket = 0x7fffffff;
      }*/

      if (!pointerCurrentPacket || (stopPacket && numCurrentPacket > stopPacket)) {

			// all the packet are generated

			ADDTOLOG1("SendingControl :: generate -- the all packets are generated");

			if (!receiver -> isWaitPackets() || (stopPacket && receiver -> getNumCurrentPacket() > stopPacket)) {

				// all the packets are received

				ADDTOLOG1("SendingControl :: generate -- the all packets are received");

            return 0;
         }
         else {

				// NOT all the packets are received

				ADDTOLOG1("SendingControl :: generate -- not all packets are received");

            if (0 == (dif = retransmit(currentTime)))

					continue;

				else {

					ADDTOLOG1("SendingControl :: generate -- instructs to wait timeout");
               return dif;
				}
         }
      }

      //dif = GetTimeDifi(currentTime, &timeCurrentPacket);
		dif = *currentTime - timeCurrentPacket;

		if (timed_mode && dif < 0) {

			ADDTOLOG1("SendingControl :: generate -- not now");
			return -dif;
      }

		// check that all the previous packets are received

      if (receiver -> getNumCurrentPacket() < numCurrentPacket) {

			// NOT all the previous packets are received

			// resend them

         if ((dif = retransmit(currentTime)) == 0)

				continue;

			else {

				ADDTOLOG1("SendingControl :: generate -- instructs to wait timeout");
            return dif;
			}
      }

#ifdef DEBUG_CONVTEST
		printf("packet %i generated (interface %i)\n", numCurrentPacket, numInterfaceForCurrentPacket);
#endif

		u_int prevNumInterfaceForCurrentPacket = numInterfaceForCurrentPacket;
		u_int prevSizeCurrentPacket = sizeCurrentPacket;

		readyBuffer(pointerCurrentPacket, sizeCurrentPacket);

		/* at first goes to the next packet
			so, the current packet will be marked as sent,
			otherwise (if we sends current packet before the marking it as sent),
			ReceivingControl may receive this packet before the mark happens,
			and the packet will be not accepted
		*/
		gotoNextPacket();

		// and now generates the saved previous packet
		if (prevSizeCurrentPacket < device -> getInterface(prevNumInterfaceForCurrentPacket) -> getMinimalSizeOfPacket())
			prevSizeCurrentPacket = device -> getInterface(prevNumInterfaceForCurrentPacket) -> getMinimalSizeOfPacket();

		ADDTOLOG3("SendingControl :: generate -- generating, interface = %i, packet = \n%s", prevNumInterfaceForCurrentPacket, getStringOfDump(bufferCurrentPacket, prevSizeCurrentPacket));

		device -> getInterface(prevNumInterfaceForCurrentPacket) -> send(bufferCurrentPacket, prevSizeCurrentPacket);

		numberOfRetransmitionsOfCurrentPacket = 0;

		timeOfFirstGeneration = *currentTime;
		timeOfLastGeneration = *currentTime;
   }
}



int SendingControl :: retransmit(const TimeStamp* currentTime) {

   int timeSinceFirstGeneration;
	int timeSinceLastGeneration;
   u_int neps;

	ADDTOLOG1("SendingControl :: retransmit -- start");

   timeSinceFirstGeneration	= (*currentTime - timeOfFirstGeneration);
	timeSinceLastGeneration		= (*currentTime - timeOfLastGeneration);

	// check if timeout from last retransmition has expired

   if (timeSinceLastGeneration >= timeout) {

      u_int gen_size1;

		ADDTOLOG1("SendingControl :: retransmit -- timeout");

      if (
			!isWaitInfinity && numberOfRetransmitionsOfCurrentPacket >= maxNumOfRetransmitions	// maximum number of retransmitions
			&& (
					!(receiver -> isWaitingFirstPacket()) || timeSinceFirstGeneration >= firstPacketTimeout
				)
			) {

			// MARK PACKET AS DROPPED

			ADDTOLOG1("SendingControl :: retransmit -- mark as dropped");

#ifdef DEBUG_CONVTEST
			printf("packet %i marked as dropped\n", receiver -> getNumCurrentPacket());
#endif

			// adds this packet to the result of test
			result.addPacket(receiver -> getNumCurrentPacket());

			/*printf("!");
			#ifndef WIN32
			fflush(stdout);
			#endif*/

			// forces the receiver to go to the next packet
         receiver -> gotoNextPacket();

      } else {

			// RETRANSMITION

			ADDTOLOG2("SendingControl :: retransmit -- retransmition, receiver packet = %i", receiver -> getNumCurrentPacket());

#ifdef DEBUG_CONVTEST
			printf("start retransmition from packet %i\n", receiver -> getNumCurrentPacket());
#endif

			// will be retransmitted the all packets from the last successfully received one

			u_char* cur = receiver -> getPointerLastReceivedPacket();

         for (;;) {

				// the algorithm is similar to 'generate' method

				u_int ngen_temp = 0;
            neps = numEPs;

            cur = file -> gotoNextEndPoint(cur, eps, &neps, &gen_size1, &ngen_temp);

            if (!cur) break;

				if (cur == pointerCurrentPacket) break;

            readyBuffer(cur, gen_size1);

#ifdef DEBUG_CONVTEST
				printf("retransmition packet %i\n", ngen_temp);
#endif
				if (gen_size1 < device -> getInterface(eps[neps].interfaceNum) -> getMinimalSizeOfPacket())
					gen_size1 = device -> getInterface(eps[neps].interfaceNum) -> getMinimalSizeOfPacket();

            device -> getInterface(eps[neps].interfaceNum) -> send(bufferCurrentPacket, gen_size1);

				ADDTOLOG2("SendingControl :: retransmit -- retransmition packet = %s", getStringOfDump(bufferCurrentPacket, gen_size1));
         }

			numberOfRetransmitionsOfCurrentPacket ++;
			timeOfLastGeneration = *currentTime;
      }

      return 0;
   }
	else {

		ADDTOLOG1("SendingControl :: retransmit -- not timeout");
	}

   return timeout - timeSinceLastGeneration;
}

void ReplaceMaker :: operator=(const ReplaceMaker& s) {

   if (filter) delete filter;

   filter = Null;
   tagval = s.tagval;
   soughVal = s.soughVal;

   if (s.filter) filter = new CommonField(*(s.filter));
   active = s.active;
}

bool ReplaceMaker :: replace(
   u_char* baseBuffer, // packet's buffer where value is sought
   u_char* modifiedBuffer, // packet's buffer where target value will be inserted
   u_int size // the minimal size of 'baseBuffer' or 'modifiedBuffer'
   ) {

   ADDTOLOG1("ReplaceMaker :: replace -- start")

   if (!active) {

      ADDTOLOG1("ReplaceMaker :: replace -- not active");
      return true;
   }

   if (filter && filter -> isContent(baseBuffer,size) != ICR_OK) {

      ADDTOLOG1("ReplaceMaker :: replace -- constraint isn't met");
      return true;
   }

   if (soughVal.isContent(baseBuffer, size) == ICR_OK) {

      ADDTOLOG1("ReplaceMaker :: replace -- is content");
      tagval.fillPacket(modifiedBuffer, size);
   }
   else {

      ADDTOLOG1("ReplaceMaker :: replace -- not content");
   }

   return false;
}

void SendingControl :: reset() {

	InteractionControl :: reset();

	timeOfLastGeneration = 0;
	timePacketToGenerate = 0;
	timeOfFirstGeneration = 0;

	numberOfRetransmitionsOfCurrentPacket = 0;
}

void ConvtestResult :: print() {

   if (!packetsNumbers.empty()) {

      UInt lastNumPac = (UInt)-1;
      bool successively = false;

      /**printf("dropped packets: "); */

      for (vector<UInt>::iterator it = packetsNumbers.begin(); it != packetsNumbers.end(); it++) {

         if (*it != lastNumPac + 1) {

            if (successively) {

               printf("-%i",lastNumPac);
            }
            if (it != packetsNumbers.begin()) printf(",");
            printf("%i", *it);
            successively = false;
         }
         else
            successively = true;

         lastNumPac = *it;
      }

      if (successively) {

         printf("-%i",lastNumPac);
      }
   }
   else
      printf("all accepted");

   printf("\n");
}

void ConvtestResult :: setByString(
   const char* listOfPackets, /* specifies array of packet, format example: 1-3;4-5;6-
                                 if the string is finished by - then all next packets in file will be also added
                                 special string "any" means all packets
                                 */
   UInt totalNumberOfPackets // the total number of packets in trace file
   ) {

   bool isRange = false;
   UInt lastPacNum = (UInt)-1;
   MString s;
   const char* c;
   const char* lc;
   const char* comma;
   const char* minus;

   c = listOfPackets;

   packetsNumbers.clear();

   if (!strCaseCompare(listOfPackets, "any")) {

      for (UInt i = 1; i <= totalNumberOfPackets; i++)
            addPacket(i);
      return;
   }

   while (c) {

      if (*c == 0 && isRange) {

         for (UInt i = lastPacNum + 1; i <= totalNumberOfPackets; i++)
            addPacket(i);
         break;
      }

      comma = strchr(c, ';');
      minus = strchr(c, '-');

      lc = c;
      if (comma < minus) c = comma;
      if (comma > minus) c = minus;
      if (!comma) c = minus;
      if (!minus) c = comma;
      if (!comma && !minus) c = Null;

      if (c && lc >= c)
         throw new Exception("incorrect syntax");

      UInt n;

      n = atoi(lc);
      if (n == 0)
         throw new Exception("incorrect syntax");

      if (isRange) {

         for (UInt i = lastPacNum + 1; i <= n; i++)
            addPacket(i);
      }
      else {

         addPacket(n);
      }

      lastPacNum = n;

      if (minus && c == minus) isRange = true;
      else isRange = false;

      if (c) c++;
   }
}
