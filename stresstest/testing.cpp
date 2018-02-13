#include "stdafx.h"
#include "testing.h"
#include "stresstest_config.h"

#ifdef TEST_MODE
Script* Testing :: scr = NULL;

#define CHECK_VAR(var,val) try { checkVar(var,val); } catch (Exception* e) { Exception* e1 = new Exception("mismatch at %s, %u", _T(__FILE__), __LINE__); delete e; throw e1;}


void Testing :: runAllTests() {
	try
	{
		cout << "Self-testing...\n";
		StresstestConfig conf;
		conf.read();

		EthDevice globalEthernetDevice;
		Network network;
		Network* globalDevice1 = &network;

		TraceFile globalTraceFile;
		ReqAndStat globalRas;

		IpTcpExpert tcpipExpert;
		AutocalcManager autocalcManager;

		Script globalScript(network, globalRas, globalTraceFile, autocalcManager, SR_NOINIT);
		globalScript.add_include_path(conf.get_base_path());
		vector<ProtocolsExpert*> experts;
		experts.push_back(&tcpipExpert);
		autocalcManager.setProtocolExperts(experts);
		vector<Device*> devices1;
		devices1.push_back(&globalEthernetDevice);
		globalDevice1 -> setDevices(devices1);
		scr = &globalScript;
		scr -> reset(SR_GEN);
		test1();
		cout << "Test1 is finished\n";
		scr -> reset(SR_GEN);
		test2();
		cout << "Test2 is finished\n";
		scr -> reset(SR_GEN);
		test3();
		cout << "Test3 is finished\n";
		scr -> reset(SR_GEN);
		test4();
		cout << "Test4 is finished\n";
		scr -> reset(SR_GEN);
		test5();
		cout << "Test5 is finished\n";
		scr -> reset(SR_GEN);
		fieldValueTest();
		cout << "Test5 is finished\n";
		scr -> reset(SR_GEN);
		testShortVarDefines();

		DBuffer :: test();

		cout << "Self-test is finished successfully\n";
	}
	catch (Exception* e) {

		cout << "Self-test is finished with mismatches\n";
		printf(e -> get_message());
		getchar();
	}
}


void Testing :: test1() {

	u_char dump[100];

	// field with size = 1

	scr -> run("filename",

		"MASK 0xff \
		 .field 0x00 \
		  field 0x56"
		);

	scr -> buf -> cpyBuf(dump, 100);
	check(!memcmp(dump, "\x56", 1));
	scr -> buf -> reset();

	scr -> run("filename",

		"MASK 0xf0 \
		 .field 0x00 \
		  field 0x56"
		);

	scr -> buf -> cpyBuf(dump, 100);
	check(!memcmp(dump, "\x50", 1));
	scr -> buf -> reset();

	scr -> run("filename",

		"MASK 0x0f \
		 .field 0x00 \
		  field 0x56"
		);

	scr -> buf -> cpyBuf(dump, 100);
	check(!memcmp(dump, "\x06", 1));
	scr -> buf -> reset();

	// field with size = 2

	scr -> run("filename",

		"MASK 0xf00f \
		 .field 0x6140 \
		  field 0x1256"
		);

	scr -> buf -> cpyBuf(dump, 100);
	check(!memcmp(dump, "\x10\x06", 2));
	scr -> buf -> reset();

	// field with large size

	scr -> run("filename",

		"MASK   0xfffff0fffffffffffffff0ff \
		 .field 0x112233445566778899aabbcc \
		  field 0x112233445566778899aabbcc"
		);

	scr -> buf -> cpyBuf(dump, 100);
	check(!memcmp(dump, "\x11\x22\x30\x44\x55\x66\x77\x88\x99\xaa\xb0\xcc", 12));
	scr -> buf -> reset();


	scr -> run("filename",

		"MASK   0x00000f000000000000000f00 \
		 .field 0x112233445566778899aabbcc \
		  field 0x112233445566778899aabbcc"
		);

	scr -> buf -> cpyBuf(dump, 100);
	check(!memcmp(dump, "\x00\x00\x03\x00\x00\x00\x00\x00\x00\x00\x0b\x00", 12));
	scr -> buf -> reset();

	// decimal value

	scr -> run("filename",

		"MASK 0xf0 \
		 .field 0x00 \
		  field 32"
		);

	scr -> buf -> cpyBuf(dump, 100);
	check(!memcmp(dump, "\x20", 1));
	scr -> buf -> reset();

	// two-byte decimal value

	scr -> run("filename",

		"MASK 0x0f00 \
		 .field 0x0000 \
		  field 20054"
		);

	scr -> buf -> cpyBuf(dump, 100);
	check(!memcmp(dump, "\x0e\x00", 2));
	scr -> buf -> reset();

	// mask's size is less than field's size

	scr -> run("filename",

		"MASK 0xff \
		 .field 0x0000 \
		  field 0x4455"
		);

	scr -> buf -> cpyBuf(dump, 100);
	check(!memcmp(dump, "\x00\x55", 2));
	scr -> buf -> reset();

	// mask with leading 00

	scr -> run("filename",

		"MASK 0x00ffff \
		 .field 0x0000 \
		  field 0x4455"
		);

	scr -> buf -> cpyBuf(dump, 100);
	check(!memcmp(dump, "\x44\x55", 2));
	scr -> buf -> reset();
}



void Testing :: test2() {

	u_char dump[100];

	// one-byte value

	scr -> run("filename",
		".field1 0x33 \
		.field2 0x45 \
		INC \
		field2 0x45");

	scr -> buf -> cpyBuf(dump, 100);
	check(!memcmp(dump, "\x33\x45", 2));

	scr -> performAutoincrement();
	scr -> buf -> cpyBuf(dump, 100);
	check(!memcmp(dump, "\x33\x46", 2));

	scr -> performAutoincrement();
	scr -> buf -> cpyBuf(dump, 100);
	check(!memcmp(dump, "\x33\x47", 2));

	scr -> performAutoincrement();
	scr -> buf -> cpyBuf(dump, 100);
	check(!memcmp(dump, "\x33\x48", 2));

	for (int i = 0; i < 255; i++)
		scr -> performAutoincrement();

	scr -> buf -> cpyBuf(dump, 100);
	check(!memcmp(dump, "\x33\x47", 2));


	scr -> buf -> reset();

	// two-bye value

	scr -> run("filename",
		".field1 0x33 \
		 .field2 0x6677 \
		 INC \
		 field2 32");

	scr -> buf -> cpyBuf(dump, 100);
	check(!memcmp(dump, "\x33\x00\x20", 3));

	scr -> performAutoincrement();
	scr -> buf -> cpyBuf(dump, 100);
	check(!memcmp(dump, "\x33\x00\x21", 3));

//	for (int i = 0; i < 65000; i++)
//		scr -> performAutoincrement();
//
//	scr -> buf -> cpyBuf(dump, 100);
//	check(!memcmp(dump, "\x33\xfe\x09", 3));
//
//	for (int i = 0; i < 65536; i++)
//		scr -> performAutoincrement();
//
//	scr -> buf -> cpyBuf(dump, 100);
//	check(!memcmp(dump, "\x33\xfe\x09", 3));

	// with custom offset

	scr -> buf -> reset();

	scr -> run("filename",
		".field1 0x33 \
		 OFFSET 4 \
		 .field2 0x6677 \
		 INC \
		 field2 32");

	scr -> buf -> cpyBuf(dump, 100);
	check(!memcmp(dump, "\x33\x02\x00", 3));

	scr -> performAutoincrement();
	scr -> buf -> cpyBuf(dump, 100);
	check(!memcmp(dump, "\x33\x02\x10", 3));
}


void Testing :: test3() {

		u_char dump[100];




	scr -> run("filename",
		"OFFSET 2 \
		.field1 0x10 \
		field1 3 \
		.field2 0x10 \
		field2 3 \
		");

	scr -> buf -> cpyBuf(dump, 100);
	check(!memcmp(dump, "\x0c\x03", 2));

	scr -> buf -> reset();

	scr -> run("filename",
		"\
		.field2 0x10 \
		field2 0xcc \
		OFFSET 7 \
		.field1 0x11 \
		field1 3 \
		");

	scr -> buf -> cpyBuf(dump, 100);
	check(!memcmp(dump, "\xcc\x80", 2));
}


void Testing :: test4() {

		u_char dump[100];




	// simple fields

	scr -> buf -> reset();
	scr -> run("filename",
		"\
		POS 3	 \
		.field 0x56 \
		field 56 \
		");

	scr -> buf -> cpyBuf(dump, 100);
	check(!memcmp(dump, "\x00\x00\x00\x38", 4));

	scr -> buf -> reset();
	scr -> run("filename",
		"\
		POS 3	 \
		.field 0x5678 \
		field 4589 \
		");

	scr -> buf -> cpyBuf(dump, 100);
	check(!memcmp(dump, "\x00\x00\x00\x11\xed", 5));

	// POS and BACK

	scr -> buf -> reset();
	scr -> run("filename",
		"\
		POS 5	 \
		BACK 2 \
		.field '' \
		field 'ab ab' \
		");

	scr -> buf -> cpyBuf(dump, 100);
	check(!memcmp(dump, "\x00\x00\x00\x61\x62\x20\x61\x62", 8));

	// hexadecimal values

	scr -> buf -> reset();
	scr -> run("filename",
		"\
		POS 5	 \
		BACK 2 \
		.field 45s2 \
		field 0x4566 \
		");

	scr -> buf -> cpyBuf(dump, 100);
	check(!memcmp(dump, "\x00\x00\x00\x45\x66", 5));
}

void Testing :: test5() {

   scr -> run("filename1",
		"var (p, td, '0')");

   // defines
   scr -> clearDefines();
	scr -> run("filename2",
		"\
       define h1 sdf\
       p = '$h1$'\
		");
	CHECK_VAR("p", "sdf");

   scr -> clearDefines();
	scr -> run("filename3",
		"\
       define h1 \"sdf\"\
       p = '$h1$'\
		");
	CHECK_VAR("p", "sdf");

   scr -> clearDefines();
   scr -> run("filename4",
		"\
       gdef h1 sdf\
       p = '$h1$'\
		");
	CHECK_VAR("p", "sdf");

   scr -> clearDefines();
   scr -> run("filename5",
		"\
       gdef s2 s3\
       gdef s1 s2\
       p = '$s1$'\
		");
	CHECK_VAR("p", "s3");

   scr -> clearDefines();
   scr -> run("filename6",
		"\
       gdef k2 k3\
       gdef k1 '$k2$'\
       p = '$k1$'\
		");
	CHECK_VAR("p", "k3");

   // recursive defines with variables
   scr -> clearDefines();
   scr -> run("filename7",
		"\
       var (p1,td,'1')\
       gdef k2 p1\
       gdef k1 '$k2$'\
       p1 = \"5\"\
       p = '$k1$'\
		");
	CHECK_VAR("p", "5");

   scr -> clearDefines();
   scr -> run("filename8",
		"\
       var (p1,td,'1')\
       gdef k2 \"p1\"\
       gdef k1 '$k2$'\
       p = '$k1$'\
		");
	CHECK_VAR("p", "p1");

   scr -> clearDefines();
   scr -> run("filename9",
		"\
       var (p1,td,'1')\
       gdef k4 p1\
       gdef k3 k4\
       gdef k2 k3\
       gdef k1 '$k2$'\
       p1 = '45'\
       p = '$k1$'\
		");
	CHECK_VAR("p", "45");

   scr -> clearDefines();
   scr -> run("filename10",
		"\
       var (p1,td,'1')\
       gdef k2 '$p1$'\
       gdef k1 '$k2$'\
       p1 = '56'\
       p = '$k1$'\
		");
	CHECK_VAR("p", "56");

   scr -> clearDefines();
   scr -> run("filename11",
		"\
       var (p3,td,\"varr\")\
       var (p1,td,'0')\
       define k2 '$p1$'\
       define k1 '$k2$'\
       p1 = '$p3$'\
       p = '$k1$'\
		");
	CHECK_VAR("p", "varr");

   scr -> clearDefines();
   scr -> run("filename12",
		"\
       var (p4,td,'varr')\
       var (p3,td,'$p4$')\
       var (p1,td,'0')\
       define k2 '$p1$'\
       define k1 '$k2$'\
       p4 = 'lan'\
       p1 = p3\
       p = '$k1$'\
		");
	CHECK_VAR("p", "varr");

   // replace command by gdef
   scr -> clearDefines();
   scr -> run("filename13",
		"\
       gdef myvar var\
       myvar (n1,num,1)\
		");
	CHECK_VAR("n1", "1");

   // display large hexadecimal
   scr -> clearDefines();
   scr -> run("filename14",
		"\
       n1=0x112233445566778899aabbccddeeff1100\
       p1='$n1$'\
		");
   CHECK_VAR("p1", "11:22:33:44:55:66:77:88 :: 99:aa:bb:cc:dd:ee:ff:11\n00");

}

void Testing :: testShortVarDefines() {
	scr -> clearDefines();
   scr -> run("filename1",
		"\
       STRING s1 = '' \
       STRING s2 = 'gh' \
       INT i1 = 3 \
       INT i2 = 33334s2 \
       HEX h1 = 0x1122 \
       HEX h2 = 10 \
       s1 = 'string1' \
       \
		");
   CHECK_VAR("s1", "string1");
   CHECK_VAR("s2", "gh");
   CHECK_VAR("i1", "3");
   CHECK_VAR("i2", "33334");
   CHECK_VAR("h1", "1122");
	if (sizeof(decimal_number_type) == 4) {
		CHECK_VAR("h2", "0000000a");
	}
	else {
		CHECK_VAR("h2", "00:00:00:00:00:00:00:0a");
	}
}

void Testing :: checkVar(const TCHAR* var, const TCHAR* val) {
   MessageString aval = scr -> getVariables().getVariable_const(MessageString(var)) -> getValueConst().getValueString(false);
   check(aval == MessageString(val));
}

void Testing :: fieldValueTest() {

	Fields fields;

	fields.addfield("srcip", 34, IPv4AddressType::TYPE);

	//CommonField f;
	CommonField g(fields, "srcip");

	check(g.getPositionInPacket() == 34);

	// tests offsetBuffer

	int sizeBuf = 20;
	u_char* buf = new u_char[sizeBuf];
	int offset = 1;
	char str[] = "\xaa\xaa\xaa\x00";
	memcpy(buf, str, strlen(str));
	FieldValue :: offsetBuffer(buf, strlen(str), offset);

	check(!memcmp(buf, "\x55\x55\x54", strlen(str)));
	FieldValue :: offsetBuffer(buf, strlen(str), -offset);
	//printf(getStringOfDump(buf, strlen(str)));
	check(!memcmp(buf, "\x2a\xaa\xaa", strlen(str)));
	FieldValue :: offsetBuffer(buf, 0, 1);
	check(!memcmp(buf, "\x2a\xaa\xaa", strlen(str)));
	FieldValue :: offsetBuffer(NULL, 0, 1);

	// tests applyMask

	FieldMask mask;

	mask.setWholeField();

	memcpy(buf, "\xff\xff\xff", 3);
	FieldValue :: copyWithMask(buf, sizeBuf, (u_char*)"\x00\x00\x00", 3, mask);
	check(!memcmp(buf, "\x00\x00\x00", 3));

	mask.setValue("0xff");

	FieldValue :: copyWithMask(buf, sizeBuf, (u_char*)"\xff\xff\xff", 3, mask);
	check(!memcmp(buf, "\x00\x00\xff", 3));

	mask.setValue("0xf0ff");

	FieldValue :: copyWithMask(buf, sizeBuf, (u_char*)"\xff\xff\x00", 3, mask);
	check(!memcmp(buf, "\x00\xf0\x00", 3));

	mask.setValue("0xf00fff");
	FieldValue :: copyWithMask(buf, sizeBuf, (u_char*)"\xff\x0f\xff", 3, mask);
	check(!memcmp(buf, "\xf0\xff\xff", 3));

	delete[] buf;
}

#endif // TEST_MODE
