#include "stdafx.h"
#include "convtest.h"

#include "stresstest_script.h"

Convtest :: Convtest() {
		
	needBreak = false;
	file = Null;
	device = Null;
	fields = Null;

	interaction = Null;

	defaultTimeout = SendingControl :: defaultTimeout;
	
	setDefaultParameters();
}


void Convtest :: setDefaultParameters() {

	startPacket = 0;
	stopPacket = 0;

	timedMode = false;
	
	//defaultTimeout = SendingControl :: defaultTimeout;
	defaultNumberOfRetransmitions = 1;

	receivingEPs.clear();
	generatingEPs.clear();

	arepMakers.clear();
	repMakers.clear();

	cieves.clear();
}

Convtest :: ~Convtest() {

	vector<EndPoint> :: iterator i;

	for ( i = generatingEPs.begin() ; i != generatingEPs.end(); i++) 
		delete (*i).f;

	for ( i = receivingEPs.begin() ; i != receivingEPs.end(); i++) 
		delete (*i).f;
}


void Convtest :: addRepMaker(Script* text, bool onlyReadText) {

	MString word;	
	bool isRecv = false;

	try
	{
		//word = text -> read_word(true);
		int kwID = text -> readValue(&word, true, false);

		if (kwID == KW_RECV_POINT)

			isRecv = true;

		else {

			if (kwID != KW_GEN)
				throw new Exception("given '%s' but expected the type of replacement (%s or %s)", !word, text -> getKeyWord(KW_RECV_POINT),
					text -> getKeyWord(KW_GEN));
		}
	}
	ADD_TO_ERROR_DESCRIPTION("reading the type of replacement");

	CommonField* field1 = Null;
	CommonField* field2 = Null;

	try
	{
		//word = text -> read_word(true);
		text -> readNameEntity(&word);
		field1 = new CommonField(*fields, !word);		
		field2 = new CommonField(*fields, !word);
	}
	ADD_TO_ERROR_DESCRIPTION("reading the name of field which value will be replaced");

	try
	{
		//word = text -> read_word(true);		
		processValueDefinition(text, field1);
	}
	ADD_TO_ERROR_DESCRIPTION("reading the sought value for given field");

	try
	{
		//word = text -> read_word(true);
		processValueDefinition(text, field2);
	}
	ADD_TO_ERROR_DESCRIPTION("reading the value to set for given field");

	if (!onlyReadText) {

		ReplaceMaker rm(field1, field2);
      FieldReplace fr = {rm, isRecv ? RM_REC : RM_GEN};
		repMakers.push_back(fr);
	}

	delete field1;
	delete field2;
}



void Convtest :: addARepMaker(const CommonField& field) {
				
	AdaptiveRepmaker arm;
	if (repMakers.size() < 2) {

		throw new Exception("needs at least two replacement definitions before");
	}

	if (repMakers[repMakers.size() - 2].status != RM_REC) 
		throw new Exception("the next to last defined replacement must has the type of receiving");

	if (repMakers[repMakers.size() - 1].status != RM_GEN) 
		throw new Exception("the last defined replacement must has the type of generating");

	if (!(repMakers[repMakers.size() - 1].rm.getTargetVal() -> getSizeField()
			==
		 repMakers[repMakers.size() - 2].rm.getTargetVal() -> getSizeField()
		 ))

		 throw new Exception("the field's sizes of two previously defined replacements must be equal");

	repMakers[repMakers.size() - 1].rm.setActive(false);
	repMakers[repMakers.size() - 2].rm.setActive(false);

	arm.init(&repMakers, repMakers.size() - 2,repMakers.size() - 1);
	arm.addFilter(field);

	FieldAdaptiveReplace armInfo;
	armInfo.a = arm;
	armInfo.group = 0;

	arepMakers.push_back(armInfo);
}


void Convtest :: processValueDefinition(Script* text, CommonField* field) {

	//MString word;
	MString value;

	check(field);
	//check(*field);

	int kwID = text -> readValue(&value, true, false);

	if (kwID == KW_FIRST || kwID == KW_SECOND) {
		
		// processes some special value

		const UInt n = 2;
		CommonField* foundFields[n];

		for (int i = 0; i < n; i++)
			foundFields[i] = new CommonField(*field);

		UInt numFound = file -> findAllFields(foundFields, n);

		UInt numRequiredField = 0;
		if (value == "second") numRequiredField = 1;

		if (numFound <= numRequiredField) 
			throw new Exception("too few packets with fields of given type in file (total = %u)", numFound);

		//delete *field;

		*field = *(foundFields[numRequiredField]);

		for (int i = 0; i < n; i++)
			delete foundFields[i];
	}
	else {

		// processes common value (numbers and others)
				
		field -> readValue(!value);
	}
}



void Convtest :: addEndPoint(Script* text, bool onlyReadText) {

	bool recvEP = false;

	userCheck(fields);
	userCheck(device);
	userCheck(file);

	MString word;	

	// processes the destination type of end point

	try
	{
		//word = text -> read_word(true);
		int kwID = text -> readValue(&word, true, false);
		
		if (kwID == KW_RECV_POINT) 

			recvEP = true;

		else {

			if (kwID != KW_GEN)
				throw new Exception("given '%s' but expected the type of end point (%s or %s)", !word, text -> getKeyWord(KW_RECV_POINT),
					text -> getKeyWord(KW_GEN));
		}
	}
	ADD_TO_ERROR_DESCRIPTION("reading the type of end point");
	
	// processes the number of interface

	text -> read_word(word, true);
	UInt interfaceNum = device -> getInterfaceNumberByName(word, true);

	// processes the name of field (type of endpoint)

	CommonField* field = 0;

	try
	{
		//word = text -> read_word(true);
		text -> readNameEntity(&word);
		field = new CommonField(*fields, !word);	
	}
	ADD_TO_ERROR_DESCRIPTION("reading the name of field for end point");

	// processes the value of end point

	try
	{
		//word = text -> read_word(true);		
		processValueDefinition(text, field);
	}
	ADD_TO_ERROR_DESCRIPTION("reading the value of field");

	// adds the end point to array

	if (!onlyReadText) {

		EndPoint ep;
		ep.f = new CommonField(*(field));
		ep.interfaceNum = interfaceNum;

		if (recvEP) {

			receivingEPs.push_back(ep);
		}
		else {

			generatingEPs.push_back(ep);
		}
	}

	delete field;
}



void Convtest :: run() {

	EndPoint* genEps = new EndPoint[generatingEPs.size()];
	EndPoint* recvEps = new EndPoint[receivingEPs.size()];

	userCheck(device);
	userCheck(file);	

	vector<EndPoint> :: iterator ep;

	UInt i;

	for ( i = 0, ep = generatingEPs.begin() ; ep != generatingEPs.end(); ep++, i++) {

		genEps[i].f = (*ep).f;
		genEps[i].interfaceNum = (*ep).interfaceNum;
	}

	for ( i = 0, ep = receivingEPs.begin() ; ep != receivingEPs.end(); ep++, i++) {

		recvEps[i].f = (*ep).f;
		recvEps[i].interfaceNum = (*ep).interfaceNum;
	}		

	interaction = new ConvImit();

	interaction -> setReceiveEPs(recvEps, receivingEPs.size());
	interaction -> setSendEPs(genEps, generatingEPs.size());	

	interaction -> setFile(file);
	interaction -> setDevice(device);
	interaction -> setTimeout(defaultTimeout);
	interaction -> setNumberOfRetransmitions(defaultNumberOfRetransmitions);	

	interaction -> setReferenceToExternalReplaces(&repMakers);
	interaction -> setReferenceToExternalARepMakers(&arepMakers);
	interaction -> setReferenceToExternalCieves(&cieves);

	interaction -> setPacketRange(startPacket, stopPacket);
	interaction -> sender.timed_mode = timedMode;

	interaction -> reset();	

	runConvtest();

	lastResult = interaction -> sender.result;

	delete interaction;	

	interaction = Null;

	delete genEps;
	delete recvEps;
}


void Convtest :: addCieve(const CommonField& field) {

	cieves.push_back(field);
}


bool Convtest :: packetHandler(UChar* buffer, UInt sizeBuf, int numReceivingInterface) {

	if (!interaction) return false;

	if (interaction -> receiver.newPacketReceived(buffer, sizeBuf, numReceivingInterface))
		packetReceivedEvent.setEvent();

	return false;
}


void Convtest :: runConvtest() {

	bool firstPacket = true;
	int numActiveInteractions = 1;
	TimeStamp time_stamp;
	int waitInterval = 0;

#ifdef WIN32
	u_int start_time = GetTickCount();
#else		
	struct timespec timeout;
	struct timeval now;
	TimeStamp start_time;
	check(-1 != gettimeofday((struct timeval*)&start_time,0));
#endif	

	for (;;) {

		if (needBreak) break;

		if (!firstPacket) {

			//printf("waits for %i milliseconds\n", waitInterval);
			packetReceivedEvent.wait(waitInterval/1000);
		} 
		else firstPacket = false;
		
#ifdef WIN32
		u_int time = GetTickCount() - start_time;      
		time_stamp.sec = time / 1000;
      time_stamp.usec = (time % 1000) * 1000;
#else
		gettimeofday((struct timeval*)&time_stamp,0);
		GetTimeDif(&time_stamp,&start_time);
#endif

		waitInterval = 0x7fffffff;

		for (int i = 0; i < 1; i++) {

			int t;

			t = interaction -> sender.generate(&time_stamp);

			if (!t) {

				numActiveInteractions--;
				if (!numActiveInteractions) break;
				else continue;
			} 
			else {

				if (t < waitInterval) waitInterval = t;
			}
		}

		if (!numActiveInteractions) break;
	} 	  
}
