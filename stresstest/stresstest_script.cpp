#include "stdafx.h"
//#include <regex>
#include "stresstest_script.h"
#include "logman.h"

#ifdef WIN32
#include "Mmsystem.h"
#endif

#define MAIN_INTERFACE_NOT_SET (-1)
#define WORD_SIZE 1600

// key words - correspond to KW_ enumeration
KeyWordsInfo key_words[]=
{
 {"SEND","{accept | drop | any }","In common regime generates the packet defined above. In other regimes (testing packet filter, see command FASTTEST and option -c) may simply separate packets one from another, so by this command the current content of buffer will be fixed and the new packet will be registered. The requests after command don't make sense in common regime (only while testing packet filter)."},
 {"PAUSE","<number of milliseconds>","Pauses the execution for a specified interval of time."},
 {"DROP","{accept | drop | any }","Request specification. The request that the packet must not be received. May be used as command - replacement for \"SEND DROP\". It may be processed as command while testing packet filter only (command FASTTEST or option -c). In common regime it may be among parameters to command only."},
 {"ACCEPT","{accept | drop | any }","Request specification. The request that the packet must be received. Analog of SEND ACCEPT. It may be processed as command while testing packet filter only (command FASTTEST or option -c). In common regime it may be among parameters to command only."},
 {"ANY","{accept | drop | any }","Request specification. No requests: the packet may be received or not. Analog of SEND ANY. It may be processed as command while testing packet filter only (command FASTTEST or option -c). In common regime it may be amoung parameters to command only. This special word may also be used as value for field that means exclusion the all conditions with this field from current mask of packet - value of the field may be any."},
 {"REP","<the number of generation>","The next generation command (command SEND) will generate not one, but several packets.\nThe use of this command also affects the request for packet: the packet must be accepted the specified number of times."},
 {">>","{accept | drop | any }","Analog of ACCEPT."},
 {"<<","{accept | drop | any }","Analog of DROP."},
 {"CLEARMASK","no parameters","The mask of packet (the set of previously defined conditions) will be cleared. New mask will correspond to any packet. This command is usually contained in headers to make the mask correspond to all packets of given type (ex: TCP packets)."},
 {"INC","","The field for which the value will be specified below becomes autoincremented. While generating several packets (command REP) the value of field will be incremented. See \"samples/synflood.fws\""},
 {"OFFSET","<number of bites>","The position of the next defined field will be shifted to the left for the given <number of bits> which must be from 1 to 7. So every written value will be shifter to the left before writing. Nevertheless, after the writing the left bits will be also changed and set to 0. To avoid this use command MASK. See \"headers/tcp_header.fws\""},
 {"DEFAULTS","{accept | drop | any | revers }","Defines default requests for packets. These requests will be applied when there are not enough explicitly defined requests for some packet (specified as parameters to command SEND, WAIT and its analogs). Initially default requests are ACCEPT ANY ANY... i.e. a single request for the first interface specified via option -d."},
 {"INCLUDE","<name of file>","Starts processing the content of given file. The search of file will be performed in the current directory, all search paths (see option -I). For every path the content of samples, headers, traces folders will be also examined. You can also type just the name of file without include before it."},
 {"DEVICE","<type of device> {<name of interface>}","Reopens interfaces. The type of device: eth, ip, tcp. The name of device is the same as for -d option, depends on the type of device. New line terminates the list of names."},
 {"WAIT","{accept | drop | any }","Waits for packet whose mask is defined above. The command will finish work when such packet is received on waitable interface. The waitable interface is interface for which strict request (accept or drop) have been specified in parameters to command or in defaults (command DEFAULT). For TCP device the command will only wait data on the main interface. In the general case command may wait no one but several packets (added by ADD command). If any of them is received then command terminates. Command waits packets until timeout expires (command TIMEOUT). See \"samples/waiting_packets.fws\"."},
 {"EXIT","<status>","Terminates the execution. The status may be some decimal number. Value 0 is reserved for successful test, 1 - fatal error, 2 - not successful test, 3 - error while TCP connecting or listening (timeout expires)."},
 {"PASS","<number of bytes>","Increases the byte pointer for the given <number of bytes>."},
 {"DEFINE","<name> <value>","Defines the substitution which will be applied while reading some values (in parameters to commands and others). <name> will be replaced by <value>. This substitution may be also performed in strings enclosed in apostrophes. In this case the <name> must be enclosed in $ (ex: 'value = $name$'. See also command GDEF."},
 {"MASK","<field's mask>","Defines the mask for the next defined field. Mask is hexadecimal number. Value for field will be written only in bits corresponding not null bits of mask. See \"headers/tcp_header.fws\"."},
 {"POS","<new position> | <field's name>","Sets the <new position> of byte pointer. In the case of <field's name> new position will be equal to field's position."},
 {"BACK","<number of bytes>","Reduces the pointer for the given <number of bytes>."},
 {"CLEARHISTORY","no parameters","Clears info about the maximum size of previous packets. New packet may be smaller than previous ones. This command also makes all auto-calculated values inactive."},
 {"VAR","<name of variable> <name of field> <initial value> (\"autoset\"| [\"static\"] )","Command creates the new variable <name of variable> or reinitializes the old one if some variable of the same name is already exist. The newly created variable will have the same value's type as <name of field>. This command also sets the <initial value> for variable. Variable's value is stored separately from packet's buffer. The \"autoset\" type of variable indicates that the variable will be initialized by received packet (while using WAIT command or its analogs), i.e. from received packet will be obtained value of <name of field> and copied to variable. \"static\" type indicates that variable must not be changed while receiving packet. The \"static\" keyword may be omitted only if parameters to command are enclosed in round brackets.\nThe <name of variable> may appear among parameters to other commands. In this case it will be replaced by its value. Such a replacement will be also performed in strings enclosed in apostrophes. In this case the <name of variable> must be enclosed in $ (ex: 'value of variable = $name$').\nSee \"samples/ask_mac.fws\", \"samples/variables.fws\"."},
 {"NAME","<name of packet>","Defines the name of currently described packet which will be displayed in report instead of not obvious \"Packet on line ...\""},
 {"MES","<string of message>","Defines the message which will be displayed the every time on receiving the currently described packet. Substitutions are allowed in the form of $name$. The 'name' may reference to the field's name, variable's name, someone defined by GDEF command. In the case of field's name field's value will be retrieved from the content of received packet."},
 {"EXTENDED","no parameters","Enables extended regime. Generating interface can be change by MI command. While specifying the requests for packet each request must be followed by the unique name of interface."},
 {"MI","<name of interface>","Sets the main interface at which packets will be generated or waited (by default it's the first opened interface). The unique name of interface must be specified which may be defined while opening (-d option or OPEN command) after symbol # (e.g. \"-d eth0#0\"). If no unique name is specified then it will be assigned to number 0,1,2,3,... Default requests are being overwritten: a single ACCEPT request is set for the new main interface, others are ANY. This means that further WAIT command (its analogs) will wait packet ONLY at the new main interface. In order to wait a packet at several interfaces use command DEFAULTS after command MI or explicitly specify requests after WAIT command."},
 {"REVERS","not command","Request specification. May only be given in parameters for DEFAULT command. Instructs to reverse the request for every packet."},
 {"BEEP","no parameters","Plays the sound via PC speaker."},
 {"SAFETERM","no parameters","If the intensity of packets is very high and the program fails in deadlock on terminating, then this command will help. Terminating may become slower."},
 {"INTERVAL","<number of milliseconds>","Sets the value of interval between generating multiple packets while using command REP."},
 {"INCVAR","<name of variable> <value to add>","Increases the given <name of variable> for the specified <value to add>. The <value to add> may be negative."},
 {"TOWAIT","{accept | drop | any }","Analog of WAIT command. Adds the above packet to the set of packets which will be waited by command WAIT or its analogs. This command does not start actual waiting (doesn't suspend script execution). Nevertheless, just after adding the packet may be registered as received. If some packet is registered as received before the call to WAIT (WAITALL) then the command will ignore it and wait for a next packet (see also SENDWAITOTHER)."},
 {"GDEF","<new name> <original name>","Defines the substitution which will be applied while reading almost any read word from text. <New name> will be replaced by <original name>. This substitution may be also performed in strings enclosed in apostrophes. In this case the name must be enclosed in $ (ex: 'value = $name$')."},
 {"TIMEOUT","<interval in milliseconds>","Defines the timeout for WAIT command (and its analogs), also for imitation of application's work. Null value means infinite timeout (such timeout will not be applied for imitation of application's work). In the case of negative value its absolute value will be obtained as timeout, but WAIT command (its analogs) will work differently: it will always wait for the whole timeout (not terminating on first received packet). So several packets may be registered as received. This command also defines the timeout for TCP server while waiting for connections."},
 {"QUIET","no parameters","Instructs to not display some annoying messages."},
 {"CYC","<number of iterations>","Command instructs that next WAIT command (its analogs) or next block of script will be processed by several times = <number of iterations>. The \"inf\" value is available which means infinite iterant processing."},
 {"SYSCALL","<command>","Implements the system call. <command> must specify command's name (path to program) with parameters. Special value CALLRES may be used to obtain the status of last system call."},
 {"NOTDOUBLEMES","no parameters","Avoids displaying of double messages (specified by command MES). It also avoids the receiving of corresponding double packets, i.e. such packets will be ignored and don't cause WAIT command (its analogs) to terminate on them."},
 {"RAND","no command","Specifies the random value for field."},
 {"PRECISEWAIT","no parameters","After the work of WAIT command (its analogs) all trace threads will be blocked until the next call to WAIT command. So there will be no missed packets between subsequent calls to WAIT command."},
 {"TRACE","<name of trace file>","Opens the given trace file for subsequent work with it."},
 {"EP","<type> <name of interface> <name of field> <field's value>","Defines an end point. While imitation of application's work the end point is a entity used for distinguishing between packets in trace file belonging to different sources (so they, for example, must be generated from different interfaces). All the packets for which the given <name of field> has the given <field's value> will belong to defined end point.\nThere are two <types> of end points: \"recv\" (receiving ep) and \"gen\" (generating ep). Generating end points search their packets in trace file and generate them. receiving end points - wait for their packets. The packets from trace file are scanned in series. The generation can only be performed after receiving previous packets. The wait will be started after generation previous packets. The <unique name of interface> specifies the interface from which packets will be generated or waited. See \"headers/configSession\""},
 {"RUN","<base request> <list of packets>","This command starts imitation of application's work. Parameters to command specify the request to result of test. <Base request> may be: drop, any, accept. List of packets, for example: 1;2;3-5;7-. Minus at the end of list means expanding to last packet in trace file. List \"any\" is equal to \"1-\".\nThe result for packets from list must correspond to base request. The result for packets not from list must correspond to inverted base request. Ex: \"run accept 1-\" means \"all packets must be accepted\", \"run drop 6-\" means \"all packets before 6 must be accepted, rest of packets - dropped\", \"run any any\" means no requests. See \"samples/convtest1\""},
 {"WRITE","no parameters","Writes the trace file opened by TRACE command on disk"},
 {"GETPAC","<number of packet>","Copies the specified packet from trace file to the buffer of current packet."},
 {"SETPAC","<number of packet>","Replaces the specified packet in trace file by the current packet."},
 {"INSPAC","<number of packet>","Insert the current packet in trace file, moving the all packets with given number and higher."},
 {"DELPAC","<number of packet>","Deletes the specified packet from trace file."},
 {"FULLMASK","no parameters","Fills the mask of packet so that the all fields will be included in mask. So while comparing packets the full packet's content will be compared. By default while describing packet's content the mask will be also added by new conditions, so the using of this command make sense only after the use of RESET command (this command is used in headers). It must be well realized that packets will be compared only by mask which is not always synchronized with packet's content."},
 {"{","no parameters","Starts the block of script. Blocks are used by some commands. This keyword cannot appear among parameters or used for something else."},
 {"}","","Terminates the block of script. This keyword cannot appear among parameters or used for something else."},
 {"IFR","<name of packet or status of last wait operation> \"{\" <block of script> \"}\" [ \"else\" \"{\" <second block of script> \"}\" ]","Processes the block of script if the last received packet (command WAIT, its analogs) has the given name (which was specified by command NAME). \"timeout\" may be specified as the name of packet what means that the block must be processed in the case of timeout. Command will not distinguish newly added packets and old ones if they have the same name. Take a note of it when using UNFIX command. See also CLEARREG command.  \nFor tcp (udp) this command is also used to check the general status of last waiting operation. Status string \"error\" may be given to check if connection is closed already. Check for timeout or error may be also performed just after opening of connection by command OPEN. See samples/tcp_gateway, samples/http_client, samples/http_server."},
 {"PRINT","<message>","Displays the given message. Use symbol \\n in message to indicate that line feed must be performed."},
 {"FILTER","<name of interface> <filter string>","Sets the fast low-level filter (which is used by tcpdump) for the given interface. The format of filter is described in libpcap (WinPcap) or tcpdump documentation. See \"samples/my_gateway\""},
 {"UNFIX","no parameters","By default after the work of WAIT command (its analogs) the statuses for all waited packets will be fixed, so there may be no packets to wait for the next call to WAIT. This command marks these old packets as newly added. The previous status for them will be lost. Take a note of that ALL old packets will be unfixed, so they will be waited: this may cause unexpected results. Consider the use of CLEARREG command."},
 {"WAITALL","no parameters","The analog of WAIT command. Doesn't add the previously defined packet to the list of waited ones. Starts waiting simply. Packets may be already added by ADD command (or using of UNFIX command)."},
 {"CHTRACE","\"{\" <block of script> \"}\"","The given block of script may contain field's values definitions or command PRINT. These definitions will be applied to every packet from trace file which corresponds the mask described before the command."},
 {"COPYREC","no parameters","The received packet (see command WAIT, its analogs) will be copied to the buffer of current packet. Precision waiting must be first enabled (command PRECISEWAIT). See also NOTCOPYREC command."},
 {"FASTTEST","no parameters","Enables fasttest regime for packet filter test. See \"samples/fasttest\"."},
 {"GETCH","no parameters","Waits for press <Enter>"},
 {"NUMRET","<number of retransmitions>","While imitation of application's work if some packets have not been received for a long time (command TIMEOUT), then the previously generated packets will be retransmitted. One retransmission by default."},
 {"RM","<type> <name of field> <sought value> <value to set>","While imitation of application's work some values in packets from trace file may be automatically replaced before generating packet or before waiting one. So the <type> of replacement (\"TORECV\" or \"TOGEN\") instructs when the replacement must be applied: before generating packet or before forming the packet which will be waited.\nSo it is possible to generate one packet but wait another. It may be useful if packets are modified on their way.\nThe <name of field> specifies the field for which the replacement must be applied. The <sought value> is the value of field which will be sought in packets to replace it. It will be replaced by the given <value to set>. Some special values are allowed: \"first\" and \"second\". In this case the concrete value will be obtained from the first or second packet in trace file. See \"headers/natConfigSession\""},
 {"ARM","<name of field> <field's value>","Defines an adaptive replacement. This command gets two previously defined replacements (command RM), marks them as not active initially. While imitation of application's work program will wait for the first packet for which the given <name of field> has the given <field's value>. Then for each of two replacements program sets its <value to set>, copying it from the received packet, then marks replacements as active. So the test will be finally configured after receiving some packet only.\nNote: from received packet will be obtained value of that field which has been specified for the first replacement. Then this value will be copied to <value to set> of second replacement.\nSee \"headers/natConfigSession\""},
 {"RANGE","<number of start packet> <number of stop packet>","While imitation of application's work the work will be performed with packets (from trace file) which are within the given range. Null value for start packet means first packet in file. Null value for stop packet means last packet in file."},
 {"HELP","<name of command> | <part of the field's name>","Displays the description of the command. The \"all\" value is available to display info about all commands. Also displays the list of fields which have the given string in their name."},
 {"TIMED","no parameters","Imitation of application's work will be implemented with considering time stamps from trace file. The test may become slower."},
 {"DEFAULTTEST","no parameters","Sets the default parameters for imitation of application's work (timeout, number of retransmitions, packets range, timed mode), removes all previously added end points (command EP) replacements (command RM), adaptive replacements (command ARM), cieves (command CIEVE). In short: full reset."},
 {"SETSIZE","<name of field> <decimal value of a new size of field>","Allows to specify the size for fields which don't have concrete size initially (strings). It can be also used to change the size for fields with concrete size (hexadecimal numbers). Value \"any\" may be used to specify the undefined size. A variable may be given so the size may be calculated before. See \"samples/http_parser\"."},
 {"IF","<value1> <type of compare> <value2> \"{\" <first block of script> \"}\" [ \"else\" \"{\" <second block of script> \"}\" ]","Processes the first block of script if condition is met, otherwise processes the second block if it is specified. <Types of compare>: = (==), !=, >, <, >=, <=. Hexadecimals number are treated as strings (with 0x prefix). If you have problems try to watch how these values are represented by string using PRINT command for example."},
 {"CURPOS","no command","This special value allows to get the current value of byte pointer."},
 {"CURSIZE","no command","This special value allows to get the current size of packet."},
 {"GOTO","<value of any type> [<stop position>]","Performs the search of the given value in current packet. The search will be started from the current position of byte pointer. Value may has any type. The result of search is available through GOTORES keyword. In the case of successful search the byte pointer will be moved to the found entry. Stop position may be equal to -1. It means search to the end of packet. Stop position may be omitted but in this case parameters must be enclosed in brackets."},
 {"GOTOB","<value of any type> [<stop position>]","Is similar to GOTO command but performs back search."},
 {"GOTORES","no command","This is a special value which allows to get the result of last search performed by GOTO or GOTOB command. 1 - successful search, 0 - not successful search."},
 {"SETPOS","<field's name> <decimal value of a new position>","Sets a new position for the given field."},
 {"DECVAR","<name of variable> <value to subtract>","Analog of INCVAR. Subtracts the given value from variable."},
 {"BREAK","no parameters","Breaks the cycle caused by using CYC command."},
 {"TORECV","no command","This special word specifies that some entity must perform its function upon the receiving of a packet."},
 {"TOGEN","no command","This special word specifies that some entity must perform its function upon the sending of a packet."},
 {"FIRST","no command","This special value retrieves field's value from the first packet in trace file."},
 {"SECOND","no command","This special value retrieves field's value from the second packet in trace file."},
 {"CIEVE","<name of field>","Causes that while imitation of application's work the value of specified field will not be considered when comparing waited packet with receiving one."},
 {"IFNDEF","<name of entity> \"{\" <script's block> \"}\"","Executes block if given entity has not been defined (entity: variable, field, someone defined by GDEF or DEFINE commands)."},
 {"CALLRES","no command","This special value allows to get the result of last system call (command SYSCALL). Only for UNIX."},
 {"MULVAR","<name of variable> <multiplier>","Multiply given variable by specified value."},
 {"DIVVAR","<name of variable> <divisor>","Divide given variable by specified value."},
 {"SENDWAIT","<requests>","Similar to SENDWAITOTHER command but also adds packet before it to wait list. Useful when you need to send a packet from one interface and receive the same one at another (when they are connected somehow)."},
 {"NOTCOPYREC","no parameters","Reverses the action of COPYREC command."},
 {"CLEARREG","no parameters","Clears the information about all the packets which were added to the waited ones (by WAIT, ADD commands). They will not be displayed in final report (or in the report that is displayed by SHOWREP command). If this command is typed at the end of script then it omits the displaying of final report (sense there are no packet in it)."},
 {"SHOWREP","no parameters","Displays a report which is the same as that displayed while program termination."},
 {"LASTRES","no command","This special value enables to get the last result of statistic analyzing performed by SHOWREP. 0 - successful, 2 - some discrepancy is found."},
 {"CURTIME","no command","This special value allows to get the current time."},
 {"PRINTL","<message>","Analog of PRINT command. Additionally performs the line feed."},
 {"FIXMASK","no parameters","Fixes the mask of packet so that the defining of field's values (also fields definitions) doesn't cause its changing."},
 {"UNFIXMASK","no parameters","Performs the action reversed to the action of FIXMASK"},
 {"LOADVAR","<name of variable> <name of file>","Loads the file in variable's current value. The variable must have undefined size: use variables with string type or use SETSIZE command."},
 {"WRITEVAR","<name of variable> <name of file>","Writes variable's value to the file on disk."},
 {"IFDEF","<name of entity> \"{\" <script's block> \"}\"","Executes block if given entity has been defined (entity: variable, field, someone defined by GDEF or DEFINE commands)."},
 {"PLAY","<name of wav file>","Windows only. Plays the specified sound, WAV-file. Sound system must be enabled. If the file is not found then default Windows sound will be played. If the file is in current folder or in standard system folder then the full path is not required (Media/<name>). \nUnder UNIX the sound will be played by PC speaker."},
 {"NEWLINEIS","<string>","Sets the string which must replace any original LF symbol while working with strings. See \"samples/strings.fws\""},
 {"SENDWAITOTHER","no parameters","Works similar to \"SEND WAITALL\" sentence. Purpose: make atomic operation. Without this command there would be a chance that a waited packet did not cause command WAITALL stop waiting if it was accepted after SEND but before WAITALL started waiting. However it would be registered as received in any case. This command should be always used when you need to send a request and RELIABLY receive a response on it never missing."},
 {"OPEN","<interface's type> <interface's name>","Opens interface of given type. Types: eth, ip, tcp, udp. For tcp this command will wait till connection with server is established or a client connection is accepted. For other types the command won't wait. See more in -d,-p,-T options."},
 {"CLOSE","<interface's name>","Closes interface with given name."},
 {"OR","","Alias of TOWAIT command."},
 {"ADD","","Alias of TOWAIT command."},
 {"RESET","","Deprecated. Use CLEARMASK"},
 {"CLEAR","","Deprecated. Use CLEARHISTORY"},
 {"RECV","","Analog of WAIT command. This command is more convenient to use when working with tcp(udp). It clears the mask of packet automatically so stops working after receiving any data. It also enables mode when received packet is copied to the buffer of current packet (COPYREC command)."},
 {"RETURN","","Stops processing current file. If it was included in another file then processing will continue from that include command."},
 {0,0,0}
};

/* Class Script */

void Script :: add_include_path(const char* path) throw(Exception*) {

	try { includePaths.add_path(new MessageString(path)); }
	ADD_TO_ERROR_DESCRIPTION("adding new path for searching header files");
}

void Script :: setCommandProcessors(vector<CommandsProcessor*> givenCommandProcessors) {
	commandProcessors.assign(givenCommandProcessors.begin(), givenCommandProcessors.end());
}

Script :: Script(Network& device, ReqAndStat& externRas, TraceFile& traceFile, AutocalcManager& autocalcManager, u_char regime)
{

	// most of parameters must be also initialized in method 'reset'

   this -> autocalcManager = &autocalcManager;

   mainInterfaceNum = MAIN_INTERFACE_NOT_SET;

	resultLastSystemCall = 0;

   numIterations = 1;

	needBreakCycle = false;

	dataWasFound = false;

	fastTestAlreadyProccessed = false;

	convtest.fields = &fields;
	convtest.device = &device;
	convtest.file = &traceFile;

	needBreak = false;

	timeoutForWaitCommand = INFINITE_WAITING;

	interval = 0;

	extendedRegime = false;

	autoIncrementedField = 0;

	text = 0;
	reg = regime;
   ras = 0;
   dev = 0;
	buf = 0;

	autoincrementEnabled = false;

	ras = &externRas;
	ras -> fields = &fields;
	ras -> substitutions = &globalDefines;
	ras -> fieldVariableValues = &variables;
	ras -> convtest = &convtest;

	set_device(&device, 0);

	reset(regime);
}

void Script :: reset(UChar newRegime) {

	ADDTOLOG2("Script :: reset -- start, regime = %i", newRegime);

	resultLastSystemCall = 0;

   numIterations = 1;

	needBreakCycle = false;

	dataWasFound = false;

	fastTestAlreadyProccessed = false;

	timeoutForWaitCommand = INFINITE_WAITING;

	interval = 0;

	extendedRegime = false;

	disableAutoincrement();

	one_packet = 0;

	numberOfGenerations = 1;

	// set defaults for ras corresponding the regime

	switch (newRegime) {

		case SR_STAT:

			ras -> setCommonDefaults(1);
			break;

		default:
			ras -> setCommonDefaults(0);
			break;
	}

	// clears some lists

	fields.clear();

	globalDefines.clear();

	variables.clear();

	buf -> reset();

	reg = newRegime;

	newpac();

	if (reg != SR_NOINIT) {

		// processes file base.fws only in SR_GEN regime

		reg = SR_GEN; // set this regime temporally

		MessageString fullNameIncludedFile;
      includePaths.search(fullNameIncludedFile, "base.fws");

		if (fullNameIncludedFile.size()) {

			try
			{
				processFile(!fullNameIncludedFile);
			}
			catch (Exception* e) {

				e -> format();
				printf("\nWarning: error while processing base.fws\n\n\t%s\n", e -> get_message());
				delete e;
			}
		}
		else {

				printf("Warning: error while opening header file base.fws.\nProgram is not correctly configured.\nYou may have some problems while searching for other header files. Consider the use of -I option. You need to specify the path to folder which contains headers and samples folders.\n");
		}
	}

	reg = newRegime;
	nameTopLevelFile.clear();
}

Script :: ~Script () {

	if (autoIncrementedField) delete autoIncrementedField;
	autoIncrementedField = 0;
	if (buf) delete buf;
}

void Script :: enableAutoincrement() {

	autoincrementEnabled = true;
	autoincrementedFieldAssigned = false;
}

void Script :: disableAutoincrement() {

	autoincrementEnabled = false;
}

void Script :: set_device (Network* dev, int mainInterfaceNum) {

	this -> dev = dev;
	this -> mainInterfaceNum = mainInterfaceNum;

	if (buf) delete buf;
	buf = Null; // don't remove it

   if (dev == Null || dev -> numOpenedInterfaces() == 0) {
      buf = new SequenceOfPackets(0x7fffffff, 0, *autocalcManager);
   }
   else {
      Device* dev1 = dev -> getInterface(getMainInterfaceNum()) -> getDevice();
      buf = new SequenceOfPackets(dev1 -> getSizeLimit(), dev1 -> getPositionDataBegins(), *autocalcManager);
   }

	autocalcManager -> fields = &fields;
}

void Script :: newpac () {

	interval = 0;

	numberOfGenerations = 1;

	disableAutoincrement();

	nameOfCurrentPacket = "";
	outputMessageForCurrentPacket = "";

	if (buf) buf -> startNewPacket();
}

void Script :: prepare_packet() {

	try {

		buf -> calcAllAutoCalcValues();
	}

	catch (Exception* e) {

		if (!ras -> quietMode) printf("Warning: %s\n", e -> get_message());
		delete e;
	}
}

CommandsProcessor* Script :: getProcessor(const MessageString& command) {
   for (int i = 0; i < commandProcessors.size(); i++) {
      if (commandProcessors[i] -> isProcessCommand(command))
         return commandProcessors[i];
   }
   return Null;
}

void Script :: processDeprecatedCommands(int kw_id) {
	const static TCHAR* mes = "command is deprecated. Use %s command.";
	if (kw_id == KW_RESET) {
		throw new Exception(mes, key_words[KW_CLEAR_MASK].keyword);
	}
	if (kw_id == KW_CLEAR) {
		throw new Exception(mes, key_words[KW_CLEAR_HISTORY].keyword);
	}
}

void Script :: runBlock(bool isIdleMode) {
   run(0,0,isIdleMode,true);
}

void Script :: run(
						 const char* filename, const char* textToProcess, bool isIdleMode, bool terminateByBlockEnd
						 ) throw(Exception*)
{

	MessageString word;
	//MessageString nameOfSource;
	StresstestTextBuffer reserveText;
	int numBlocksDepth = 0;
	bool cycleWasBefore = false;

	if (needBreak) return;

	try
	{
		StresstestTextBuffer* lastText = 0;

		if (textToProcess) {

			userCheck(filename);

			lastText = text;
			reserveText.setText(textToProcess, filename);
			text = &reserveText;
		}

		if (nameTopLevelFile.size() == 0) nameTopLevelFile = text -> getNameSource();

		userCheck(text);
		if (reg == SR_NOINIT)
         throw new Exception("script is not initialized (by reset method)");
		userCheck(buf);

		if (reg != SR_STAT) check(dev);
		check(ras);

		for (; ; ) {

			int kw_id;
			//bool runtime_kw;
			FieldVariableValue* foundVariable = 0;
			const FieldInfo* fieldParameters = 0;
         const ValueType* valueType;
         CommandsProcessor* comProcessor = Null;

			if (needBreak) break;

			// reads next word

			if (!isIdleMode) {

				kw_id = readEntity(&word, false, false, QP_NOT_PROCESS_QUOTES, true);
			}
			else {

				// while idle mode dont tries to expand strings, simply reads words

				text -> nextWord(word, false);
				kw_id = is_keyword(!word);
			}

			if (!word.size()) {
            if (terminateByBlockEnd) {
               throw new Exception("end of script block } not found, probably because of excessive { somewhere");
            }
            break;
         }

         bool found = false;

         if (kw_id != NOT_KEY_WORD) {
            found = true;
         }

         if (!found) {
            valueType = text -> getValueTypeByName(word);
            if (valueType) found = true;
         }

         if (!found) {
            comProcessor = getProcessor(word);
            if (comProcessor) found = true;
         }

			if (!found) {
            fieldParameters = fields.getField(word);
            if (fieldParameters) found = true;
         }

			if (!found) {
            foundVariable = variables.getVariable(!word, false);
            if (foundVariable) found = true;
         }

			// processes block's borders

			if (kw_id == KW_START_BLOCK) {

				ADDTOLOG3("block start : line %u : num %i", text -> getLineNumber(), numBlocksDepth);
				numBlocksDepth ++;
			}
			if( kw_id == KW_END_BLOCK) {
				ADDTOLOG3("block finish : line %u : num %i", text -> getLineNumber(), numBlocksDepth);
				numBlocksDepth--;
				if (numBlocksDepth < 0) {
					if (!terminateByBlockEnd) {
						throw new Exception("excessive }");
					}
					break;
				}
			}

			if (isIdleMode) continue;
         if (needBreakCycle) continue;

			if (kw_id == KW_EXIT) {

				MessageString s;
				UInt lastStatus;

				try {

					try
					{
						read_word(s,true);
						lastStatus = (int)s.getNumber(true, true);
					}
					ADD_TO_ERROR_DESCRIPTION("reading the value of last status");

					ras -> setLastStatus(lastStatus);

					needBreak = true;
				}
				ADD_TO_ERROR_DESCRIPTION2("command %s", key_words[KW_EXIT].keyword);

				break;
			}

			try
			{

			if (kw_id != -1) {

				ADDTOLOG2("script :: run -- command %s", key_words[kw_id]);

				processDeprecatedCommands(kw_id);

				text -> clearLastComments();

				// read ( or = before parameters

				text -> storeCurrentPosition();

				bool bracketWasTyped = false; // stores the fact that there was ( before parameters

				MessageString w1;
				read_word(w1);
				if (w1 != "(" && w1 != "=")
					text -> restoreKeptPosition();
				else {

					if (w1 == "(") bracketWasTyped = true;
				}

				// processes commands

				switch (kw_id) {

					case KW_NEWLINEIS: {

						MessageString lineFeedSubstitution;

						read_word(lineFeedSubstitution, true, true);
						text -> setLineFeedSubstitution(!lineFeedSubstitution);
						break;
					}

					case KW_PLAY: {

						MessageString filename;

						try
						{
							read_word(filename, true, true);
						}
						ADD_TO_ERROR_DESCRIPTION("reading the name of file");
#ifdef WIN32
						PlaySound(!filename, Null, SND_SYNC | SND_FILENAME);
#else
						beep();
#endif

						break;
					}

					case KW_UNFIXMASK:

						buf -> unfixMask();
						break;

					case KW_FIXMASK:

						buf -> fixMask();
						break;

					case KW_SHOWREP:

						ras -> showStatictic();
						break;

					case KW_CLEARREG:

						ras -> clearPacketsInfo();
						break;

					case KW_IFDEF:
					case KW_IFNDEF: {

						MessageString word;
						bool found = false;

						text -> nextWord(word, true);		// performs raw read, global defines must not be implemented

                  putValuesInMessage(&word);

						if (!found && variables.getVariable(!word, false)) found = true;
						if (!found && fields.getField(word)) found = true;
						if (!found && globalDefines.search_value(!word)) found = true;
						if (!found && defines.search_value(!word)) found = true;

						read_word(word, true, false);
						int kwID = is_keyword(!word);
						if (kwID != KW_START_BLOCK) {

							throw new Exception("given '%s', but expected the start of new block (%s)", !word, key_words[KW_START_BLOCK].keyword);
						}

						if (kw_id != KW_IFDEF)
							runBlock(found);
						else
							runBlock(!found);

						break;
					}

					case KW_CIEVE: {

						MessageString word;

						try
						{
							readNameEntity(&word, true);
                     CommonField f(*fields.getFieldEx(word));
                     convtest.addCieve(f);
						}
						ADD_TO_ERROR_DESCRIPTION("adding new cieve");

						break;
					}

					case KW_RETURN:
						throw new ReturnException();
						break;

               case KW_BREAK:

                  needBreakCycle = true;
                  break;

					case KW_SETPOS: {

						MessageString nameOfField;
						MessageString value;

						try
						{
							readNameEntity(&nameOfField, true);
						}
						ADD_TO_ERROR_DESCRIPTION("reading the field's name");

						UInt p;
						try
						{
							readValue(&value);
							p = (UInt)value.getNumber(true, true);
						}
						ADD_TO_ERROR_DESCRIPTION("reading the new position");

						fields.setPositionOfField(nameOfField, p);

						break;
					}

					case KW_GOTOB:
					case KW_GOTO: {

						MessageString s;
						RefHolder<FieldValue> v;
						UInt stopPosition = (UInt)-1;

						try
						{
							readEntity(&s, false, true, QP_NOT_PROCESS_QUOTES, false);
							text -> readValueUndefinedType(v, !s);
						}
						ADD_TO_ERROR_DESCRIPTION("reading the sought value");

						ADDTOLOG2("goto : %s", !s);

						readValue(&s, true);

						if (s == ")") {

							if (!bracketWasTyped) {

								throw new Exception("unexpected bracket");
							}

							bracketWasTyped = false;
						}
						else {

							try
							{
								stopPosition = (UInt)s.getNumber(true, false);
							}
							ADD_TO_ERROR_DESCRIPTION("reading the stop position for search, use enclosing brackets to omit this parameter");
						}

						ADDTOLOG2("goto : stop on %u", stopPosition);

						UInt posOfFoundEntry;
						if (kw_id == KW_GOTO) {

							posOfFoundEntry
								= buf -> getPacket().getContentOfPacket().search(*v.ref(), buf -> getPos(), stopPosition);
						}
						else {

							posOfFoundEntry
								= buf -> getPacket().getContentOfPacket().searchBack(*v.ref(), buf -> getPos(), stopPosition);
						}

						if (posOfFoundEntry == DATA_NOT_FOUND) {

							dataWasFound = false;
						}
						else {

							dataWasFound = true;
							buf -> setpos(posOfFoundEntry);
						}

						break;
					}

					case KW_DEFAULTTEST:

						convtest.setDefaultParameters();
						break;

					case KW_TIMED: {

						convtest.timedMode = true;
						break;
					}

					case KW_HELP: {

						MessageString word;

						try
						{
							read_word(word, true);
						}
						ADD_TO_ERROR_DESCRIPTION("reading the name of key word");

						printKeyWordInfo(word);
						fields.print(!word);

						break;
					}

					case KW_SETSIZE: {

						MessageString word;
						MessageString nameOfField;
                  const FieldInfo* field;

						try
						{
							readNameEntity(&nameOfField, true);
                     field = fields.getFieldEx(nameOfField);
						}
						ADD_TO_ERROR_DESCRIPTION("reading the name of field");

						try
						{
                     DefSize size = DefSize :: UNDEFINED;
							readValue(&word, true, false);
                     if (word != "any") {
                        UInt n = (int)word.getNumber(true);
                        if (n < 0)
                           throw new Exception("the size must be greater or equal to 0");
                        size = n;
                     }

                     fields.setSizeOfField(!nameOfField, size);

						}
						ADD_TO_ERROR_DESCRIPTION("reading and setting the size for field");


						break;
					}

					case KW_RANGE: {

						MessageString word;
						UInt startPacket;
						UInt stopPacket;

						BLOCK_WHILE_STAT_REGIME

						try
						{
							readValue(&word);
							startPacket = (UInt)word.getNumber(true, true);
						}
						ADD_TO_ERROR_DESCRIPTION("reading the number of start packet");

						try
						{
							readValue(&word);
							stopPacket = (UInt)word.getNumber(true, true);
						}
						ADD_TO_ERROR_DESCRIPTION("reading the number of stop packet");

						convtest.setPacketRange(startPacket, stopPacket);

						break;
					}

					case KW_RM:

						BLOCK_WHILE_STAT_REGIME

						convtest.addRepMaker(this, false);
						break;

					case KW_ARM:

						BLOCK_WHILE_STAT_REGIME

						processARepMakerCommand();
						break;

					case KW_NUMRET: {

						MessageString word;
						UInt n = 1;

						BLOCK_WHILE_STAT_REGIME

						try
						{
							readValue(&word);
							n = (UInt)word.getNumber(true, true);
						}
						ADD_TO_ERROR_DESCRIPTION("reading the number of retransmitions");

						convtest.setNumberOfRetransmitions(n);

						break;
					}

					case KW_GETCH:

						if (reg != SR_STAT) getchar();
						break;

					case KW_FASTTEST:

						if (reg == SR_GEN && !fastTestAlreadyProccessed) {

							MessageString file;

							if (nameTopLevelFile.size() == 0) {

								throw new Exception("command is not available in given context");
							}

							file = nameTopLevelFile;

							try
							{
								reset(SR_STAT);
								processFile(!file);
							}
							ADD_TO_ERROR_DESCRIPTION2("registering packets, processing from file '%s'", !file);

							mysleep(PAUSE_BEFOR_GENERATING);

							reset(SR_GEN);

							fastTestAlreadyProccessed = true;
						}

						break;

					case KW_COPYRECPACKET: {

						BLOCK_WHILE_STAT_REGIME

						if (!ras -> pauseTraceAfterFirstPacket) {

							throw new Exception("precision waiting must be at first enabled (through command %s)", key_words[KW_CAREFULWAIT].keyword);
						}

						ras -> setRefToPacket(&buf);

						break;
					}

					case KW_NOTCOPYREC:

						ras -> setRefToPacket(Null);
						break;

					case KW_CHTRACE: {

						MessageString word;

						BLOCK_WHILE_STAT_REGIME

						read_word(word, true);

						int keywordID = is_keyword(!word);
						if (keywordID != KW_START_BLOCK)
							throw new Exception("after command the start of the new block (%s) is expected", key_words[KW_START_BLOCK].keyword);

						// creating the new StresstestTextBuffer object

						StresstestTextBuffer* copyOfText = new StresstestTextBuffer();
						StresstestTextBuffer* lastText = text;
						text = copyOfText;

						Packet* prevPacket = new Packet();
						*prevPacket = *(buf -> getPacketSpecial()); // stores the current packet

						for (UInt numPac = 1; ; numPac++) {

							UChar* pacBuf;
							UInt sizePac;

							// gets packet from file and copies it to the buffer of packets sequence

							try
							{
								pacBuf = convtest.file -> getPacketByNumber(numPac, &sizePac, Null);
							}
							catch (Exception* e) {

								// NO_MORE_PACKETS

								delete e;
								break;
							}

							// checks if the current packet correspond the mask which is defined before command

							if (!prevPacket -> isPacketCorrespondsTheMask(pacBuf, sizePac)) continue;

							buf -> setFullPacket(pacBuf, sizePac);	// copies to the buffer of packets sequence

							// processing block's content

							*text = *lastText;	// !!! restores the initial parameters of StresstestTextBuffer object
							runBlock(false);

							prepare_packet();

							// sets the modified packet in trace file
							convtest.file -> replacePacket(numPac, (UChar*)!(buf -> getPacket().getContentOfPacket()), buf -> getCurrentSize());
						}

						// restores the reference to previous StresstestTextBuffer object

						text = lastText;
						*lastText = *copyOfText;
						delete copyOfText;
						delete prevPacket;

						bracketWasTyped = false;

						break;
					}

					case KW_UNFIX:

						BLOCK_WHILE_STAT_REGIME

						ras -> unfixAllResults();
						break;


					case KW_FILTER: {

						MessageString word;

						UInt n;

						try
						{
							readString(&word);
							n = ras -> getInterfaceNumByName(word, true);
						}
						// TODO[at] do not call it unique name
						ADD_TO_ERROR_DESCRIPTION("reading unique name of interface");

                  EthInterface* ethInt = dynamic_cast<EthInterface*>(dev -> getInterface(n));

						if (!ethInt)
							throw new Exception("command is not supported for current device");

						try
						{
							readStringOnly(&word);
						}
						ADD_TO_ERROR_DESCRIPTION("reading the string which describes the filter");

						try
						{
							ethInt -> setFilter((char*)word.c_str());
						}
						ADD_TO_ERROR_DESCRIPTION2("setting the filter '%s'", word.c_str());

						break;
					}

					case KW_START_BLOCK: {

						UInt n = numIterations;
						StresstestTextBuffer copyOfText;
						StresstestTextBuffer* lastText = text;

						BLOCK_WHILE_STAT_REGIME

						ADDTOLOG2("block start process : line %i", text -> getLineNumber());

						copyOfText = *text;

						text = &copyOfText;

						bool cycleWasBefore_prev = cycleWasBefore;
						cycleWasBefore = false;
                  numIterations = 1;

						try{
							if (n > 0) for (UInt i = 0; i < n && !needBreak && !needBreakCycle; i++) {
								*text = *lastText;
								runBlock(false);
							}
							else runBlock(true);
						}
						catch (Exception* e) {
							text = lastText;
							throw;
						}


						if (cycleWasBefore_prev) needBreakCycle = false;
						text = lastText;
						*text = copyOfText;
						numBlocksDepth--;

						break;
					}

					case KW_END_BLOCK:

						break;

					case KW_PRINTL:
					case KW_PRINT: {

						MessageString message;

						try
						{
							if (reg == SR_STAT)

								// resolving of references must be avoided while statistic regime
								// so not use readString method

								read_word(message, true, true);

							else {

								readStringOnly(&message);
								//readEntity(&message, false, true, true, false, true);
								//message = text -> read_word(false);
							}
						}
						ADD_TO_ERROR_DESCRIPTION("reading the string which must be displayed");

						if (reg != SR_STAT) {

							if (kw_id == KW_PRINTL) {

								//message.resize(300);
								//char ttts[10000];
								//lstrcpy(ttts, !message);
								printf("%s\n", !message);
							}
							else {

								printf("%s", !message);
							}
                     fflush(stdout);
						}

						break;
					}

					case KW_IF: {

						MessageString val1;
						MessageString val2;
						MessageString typeCompareString;
						TypeCompareField typeCompare;

						// reads first compare operand

                  //TODO[at] not quoted string must not be accepted
						try
						{
							readStringRequireQuots(&val1);
							ADDTOLOG2("KW_IF -- first item = %s", !val1);
						}
						ADD_TO_ERROR_DESCRIPTION("reading the first value");

						// reads the type of compare

						try
						{
							read_word(typeCompareString, true, false);
							typeCompare = isCompareQualifier(typeCompareString);
							if (typeCompare == TCF_UNDEFINED) {

								throw new Exception("'%s' is not type compare qualifier", !typeCompareString);
							}
						}
						ADD_TO_ERROR_DESCRIPTION("reading the type of compare");

						// reads second compare operand

						try
						{
							readStringRequireQuots(&val2);
							ADDTOLOG2("KW_IF -- second item = %s", !val2);
						}
						ADD_TO_ERROR_DESCRIPTION("reading the second value");

						bool isProcess = MaskCondition :: isConditionMet(val1, val2, typeCompare);

						// reads the optional )

						read_word(val1, true, false);

						if	(val1 == ")") {

							if (!bracketWasTyped) throw new Exception("unexpected bracket");
							read_word(val1, true, false);
						}
						else {

							if (bracketWasTyped)
								throw new Exception("the match bracket is missing");
						}

						// reads KW_START_BLOCK after the command

						int kwID = is_keyword(!val1);
						if (kwID != KW_START_BLOCK) {

							throw new Exception("given '%s', but expected the start of new block (%s)", !val1, key_words[KW_START_BLOCK].keyword);
						}

						ADDTOLOG2("KW_IF -- isProcess = %i", isProcess);

						runBlock(!isProcess);

						ADDTOLOG2("KW_IF -- line %i", text -> getLineNumber());

						processElse(isProcess);

						bracketWasTyped = false;

						break;
					}

					case KW_IFR: {

						MessageString word;
						MessageString namePacket;

						BLOCK_WHILE_STAT_REGIME

						// reads the name of target packet

						//readString(&namePacket);

						readEntity(&namePacket, false, true, QP_REMOVE_OPTIONAL_QUOTES, false);

						// reads optional ) or KW_START_BLOCK

						read_word(word, true, false);
						if (bracketWasTyped && word == ")") read_word(word, true);
						if (word != key_words[KW_START_BLOCK].keyword)
							throw new Exception("given '%s', but expected the start of new black (%s)", !word, key_words[KW_START_BLOCK].keyword);

						const MessageString nameLastReceivedPacket = ras -> getNameLastReceivedPacket();

						// processes the block

						bool isProcessBlock
							= (nameLastReceivedPacket.empty() && namePacket == "timeout")
								|| (nameLastReceivedPacket == namePacket);

						ADDTOLOG4("IFR : last rec %s, given %s, res %i", !nameLastReceivedPacket, !namePacket, isProcessBlock);

						runBlock(!isProcessBlock);

						processElse(isProcessBlock);

						bracketWasTyped = false;

						break;
					}

					case KW_FULLMASK:

						buf -> setFullMask();
						break;

					case KW_DELPAC: {

						UInt n;

						try
						{
							readValue(&word);
							n = (UInt)word.getNumber(true, true);
						}
						ADD_TO_ERROR_DESCRIPTION("reading the number of packet to delete (1-based)");

						BLOCK_WHILE_STAT_REGIME

						convtest.file -> deletePacket(n, Null);
						break;
					}

					case KW_INSPAC:
					case KW_SETPAC: {

						MessageString word;
						UInt numPac;

						BLOCK_WHILE_STAT_REGIME

						try
						{
							readValue(&word);
							numPac = (UInt)word.getNumber(true, true);
						}
						ADD_TO_ERROR_DESCRIPTION("reading the number of packet (1-based)");

						prepare_packet();

						UInt sizePac = buf -> getCurrentSize();

						if (kw_id == KW_SETPAC)
							convtest.file -> replacePacket(numPac, !(buf -> getPacket().getContentOfPacket()), sizePac);
						else
							convtest.file -> insertPacket(numPac, !(buf -> getPacket().getContentOfPacket()), sizePac);

						break;
					}

					case KW_GETPAC: {

						MessageString word;
						UInt numPac;

						try
						{
							readValue(&word);
							numPac = (UInt)word.getNumber(true, true);
						}
						ADD_TO_ERROR_DESCRIPTION("reading the number of packet (1-based)");

						UInt sizePac;

						UChar* pacBuf = convtest.file -> getPacketByNumber(numPac, &sizePac, Null);
						buf -> setFullPacket(pacBuf, sizePac);

						break;
					}

				   case KW_LOADVAR: {

						MessageString nameOfFile;
						MessageString nameOfVariable;
						FieldVariableValue* var;
						FileWorker file;

						try
						{
							readNameEntity(&nameOfVariable, true);
							var = variables.getVariable(!nameOfVariable, false);
							if (!var) {

								throw new Exception("variable with name '%s' not found", !nameOfVariable);
							}
						}
						ADD_TO_ERROR_DESCRIPTION("reading the name of variable");

						try
						{
							readString(&nameOfFile);
						}
						ADD_TO_ERROR_DESCRIPTION("reading the name of file");

						file.load(!nameOfFile);

						*((DBuffer*)&(var -> getValue())) = file;
						break;
					}

				   case KW_WRITEVAR: {

						MessageString nameOfFile;
						MessageString nameOfVariable;
						FieldVariableValue* var;
						FileWorker file;

						try
						{
							readNameEntity(&nameOfVariable, true);
							var = variables.getVariable(!nameOfVariable, false);
							if (!var) {

								throw new Exception("variable with name '%s' not found", !nameOfVariable);
							}
						}
						ADD_TO_ERROR_DESCRIPTION("reading the name of variable");

						try
						{
							readStringOnly(&nameOfFile);
						}
						ADD_TO_ERROR_DESCRIPTION("reading the name of file");

						(DBuffer&)file = var -> getValueConst();

						file.save(!nameOfFile);

						break;
					}

					case KW_WRITETRACE:

						BLOCK_WHILE_STAT_REGIME

						convtest.file -> save();
						break;

					case KW_RUN: {

						MessageString word;

						BLOCK_WHILE_STAT_REGIME

						if (!convtest.file -> isOpened()) {

							throw new Exception("trace file must be opened (command %s)", key_words[KW_OPENTRACE].keyword);
						}

						// reads the base request

						Request request;

						try
						{
							read_word(word, true);

							int kwID = is_keyword(!word);

							if (kwID == KW_SENDD || kwID == KW_BLOCK) {

								request = RAS_DROP;
							}
							else {

								if (kwID == KW_SENDA || kwID == KW_ACCEPT)
									request = RAS_ACCEPT;

								else {

									if (kwID == KW_ANY)
										request = RAS_ANY;
									else
										throw new Exception("given '%s' but expected request specification (ACCEPT, DROP or ANY)", !word);
								}
							}
						}
						ADD_TO_ERROR_DESCRIPTION("reading the request");

						MessageString requestString;
						requestString = word;

						// reads the list of packets

						ConvtestResult requestPackets;

						try
						{
							read_word(word, true);
							//printf("%s\n", !word);
							requestPackets.setByString(!word, convtest.file -> getTotalNumberOfPackets());
						}
						ADD_TO_ERROR_DESCRIPTION2("reading the list of packets (ex 1,2-5,6,5) : %s", !word);

						if (nameOfCurrentPacket.size() == 0) {

							nameOfCurrentPacket.resize(50 + text -> getShortNameSource().size());
							sprintf((char*)nameOfCurrentPacket.c_str(), "convtest on line %u (%s)", text -> getLineNumber(), !text -> getShortNameSource());
						}

						// runs imitation

						if (!ras -> quietMode) printf("Started %s\n", !nameOfCurrentPacket);

						ras -> isResendPackets = true;
						convtest.run();
						ras -> isResendPackets = false;

						// registrates the result

						ras -> addConvtest(!nameOfCurrentPacket, request,
							requestPackets, convtest.lastResult, convtest.file -> getTotalNumberOfPackets());

						nameOfCurrentPacket = ""; /* doesn't mark the description of new packet but resets 'nameOfCurrentPacket'
															  in order to next packet or test doesnt inherit this name
															*/

						break;
					}

					case KW_EP: {

						BLOCK_WHILE_STAT_REGIME

						if (!convtest.file -> isOpened()) {

							throw new Exception("trace file must be opened (command %s)", key_words[KW_OPENTRACE].keyword);
						}

						convtest.addEndPoint(this, !(reg == SR_GEN));
						break;
					}

					case KW_OPENTRACE: {

						MessageString name;

						readString(&name);

						MessageString path;
                  includePaths.search(path, !name);
						if (path.size() == 0) path = name;
						convtest.file -> load(!path);
						break;
					}

					case KW_CAREFULWAIT:

						BLOCK_WHILE_STAT_REGIME

						ras -> pauseTraceAfterFirstPacket = true;
						break;

					case KW_NOTDOUBLEMES:

						BLOCK_WHILE_STAT_REGIME

						ras -> notDisplayDoubleMessages = true;
						break;

					case KW_SYSCALL: {

						MessageString word;

						BLOCK_WHILE_STAT_REGIME

						try
						{
							readStringOnly(&word);
						}
						ADD_TO_ERROR_DESCRIPTION2("inserting substitutions in string %s", !word);

						makeSystemCall(!word);

						break;
					}

					case KW_CYC: {

						MessageString val;

						BLOCK_WHILE_STAT_REGIME

						try
						{
							readValue(&val, true);

							UInt n;

							if (val == "inf")

								n = 0xffffffff;

							else {

								n = (UInt)val.getNumber(true, true);
							}

							numIterations = n;
							cycleWasBefore = true;
						}
						ADD_TO_ERROR_DESCRIPTION("reading the number of iterations");

						break;
					}

					case KW_QUIET: {

						ras -> quietMode = true;
						Network :: quiet = true;
						break;
					}

					case KW_TIMEOUT: {

						MessageString value;
						int n;

						BLOCK_WHILE_STAT_REGIME

						try
						{
							readValue(&value);
							n = (UInt)value.getNumber(true, false);
						}
						ADD_TO_ERROR_DESCRIPTION("reading the value of timeout (in milliseconds)");

						if (n) {

							timeoutForWaitCommand = (UInt) abs(n);
							convtest.setTimeout(timeoutForWaitCommand);
						}
						else
							timeoutForWaitCommand = INFINITE_WAITING;

						TCPDevice :: timeoutInMilliseconds = timeoutForWaitCommand;

						if (n >= 0)
							ras -> waitAllPackets = false;
						else
							ras -> waitAllPackets = true;

						break;
					}

					case KW_DIVVAR:
					case KW_MULVAR:
					case KW_DECVAR:
					case KW_INCVAR: {

						decimal_number_type numToAdd;
						MessageString value;
						FieldVariableValue* var = 0;
						bool neg = false;
						bool mul = false;

						if (kw_id == KW_MULVAR || kw_id == KW_DIVVAR) mul = true;
						if (kw_id == KW_DECVAR || kw_id == KW_DIVVAR) neg = true;

						// reads the name of variable

						try
						{
							readNameEntity(&value, true);
							var = variables.getVariable(!value, false);
							if (!var) {

								throw new Exception("variable with name '%s' not found", !value);
							}
						}
						ADD_TO_ERROR_DESCRIPTION("reading the name of variable");

						// reads the value by which subtract, divide, ...

						try
						{
							readValue(&value);
						}
						ADD_TO_ERROR_DESCRIPTION("reading the value to add");

						// converting value to number

						try
						{
							numToAdd = (decimal_number_type)value.getNumber(true);
						}
						ADD_TO_ERROR_DESCRIPTION2("converting '%s' to number", !value);

						if (!mul) {

							// addition or subtraction

							if (neg) numToAdd = -numToAdd;
							var -> getValue().changeValue(numToAdd);
						}
						else {

							// multiply or divide

							MessageString value = var -> getValue().getValueString();
							decimal_number_type n;
							try
							{
								n = (decimal_number_type)value.getNumber(true);
							}
							ADD_TO_ERROR_DESCRIPTION2("converting value '%s' to number", !value);

							if (neg) n /= numToAdd;
							else n *= numToAdd;

							value.resize(40);
							value.resize(sprintf((char*)value.c_str(), DECIMAL_NUMBER_FORMAT, n));

							try
							{
								var -> getValue().readValue(!value, DefSize :: FOR_VARIABLE);
							}
							ADD_TO_ERROR_DESCRIPTION2("reading modified value %s", !value);
						}

						break;
					}

					case KW_INTERVAL: {

						MessageString value;

						try
						{
							readValue(&value);
							interval = (UInt)value.getNumber(true, true);
						}
						ADD_TO_ERROR_DESCRIPTION("reading the value of initval between sending multiple packets (in milliseconds)");
						break;
					}

					case KW_SAFETERM:

						dev -> setSafeTerm(true);
						break;

					case KW_BEEP: {

						#ifdef WIN32
						Beep(700, 100);
						#else
						beep();
						#endif

						break;
					}

					case KW_MAIN_INTERFACE: {

						MessageString s;
						UInt num;
						UInt userNumber;

						if (!extendedRegime) {

							//throw new Exception("extended regime must be activated (command %s)", key_words[KW_EXTENDED].keyword);
                     extendedRegime = true;
						}

						try
						{
							readString(&s);
							num = ras -> getInterfaceNumByName(s, true);
						}
						ADD_TO_ERROR_DESCRIPTION("reading the unique name of interface");

						setMainInterfaceNum(num);

						break;
					}

					case KW_EXTENDED:

						extendedRegime = true;
						break;

					case KW_OUTPUT_MESSAGE:

						try
						{
							read_word(outputMessageForCurrentPacket, true, true);
						}
						ADD_TO_ERROR_DESCRIPTION("reading the message which will be displayed on receiving the packet");
						break;

					case KW_NAME_OF_PACKET: {

						MessageString name;

						try
						{
							//read_word(name, true, true);
							//putValuesInMessage(name);
							readString(&name);
						}
						ADD_TO_ERROR_DESCRIPTION("reading a name of packet");

						nameOfCurrentPacket = name;

						break;
					}

					case KW_VAR:

						processVarCommand(&bracketWasTyped);
						break;

					case KW_OFFSET: {

						int offset;

						try
						{
							readValue(&word);
							offset = (int)word.getNumber(true, true);
							if (!offset) {

								throw new Exception("given '%s', but expected not zero NUMBER", !word);
							}
						}
						ADD_TO_ERROR_DESCRIPTION("reading the offset (in bits) for the next defined field");

						fields.set_def_offset(offset);

						break;
					}

					case KW_BACK: {

						int pos;

						try
						{
							readValue(&word);
							pos = (int)word.getNumber(true, true);
						}
						ADD_TO_ERROR_DESCRIPTION("reading the number of bytes which the current position of pointer will be reduced for");

						pos = buf -> getPos() - pos;
						buf -> setpos(pos);
						break;
					}

					case KW_POS: {

						UInt pos;

						try
						{

							read_word(word, true);

							// searches 'word' amoung field's names

							const FieldInfo* fieldParameters = fields.getField(word);
							if (fieldParameters) {

								pos = fieldParameters -> getPos();
							}
							else {

								// not field's name

								searchEntity(&word);

								pos = (UInt)word.getNumber(true, true);
								if (pos == 0 && strcmp(!word,"0")) {

									throw new Exception("given '%s', but expected number", !word);
								}
							}
						}
						ADD_TO_ERROR_DESCRIPTION("reading the new position of pointer (number or the name of field)");

						buf -> setpos(pos);
						break;
					}

					case KW_MASK: {

						try
						{
							read_word(word, true);
						}
						ADD_TO_ERROR_DESCRIPTION("reading the mask (hexadecimal value)");

						fields.setmask(!word);

						break;
					}

					// VALUE <value's name> <value> , Ex: VALUE http 80s2.
					case KW_GDEFINE:
					case KW_DEFINE: {

						processDefineCommand(kw_id == KW_GDEFINE);
						break;
					}

					case KW_PASS:

						UInt num;

						try
						{
							readValue(&word);
							num = (UInt)word.getNumber(true, true);
						}
						ADD_TO_ERROR_DESCRIPTION("reading the number of bytes which the current position of pointer will be increased for");

						buf -> setpos(buf -> getPos() + num);
						break;

					case KW_RECV:
						buf -> clearMask();
						ras -> pauseTraceAfterFirstPacket = true;
						ras -> setRefToPacket(&buf);

					case KW_SENDWAITOTHER:
					case KW_SENDWAIT:
					case KW_WAITALL:
					case KW_OR:
					case KW_ADD:
					case KW_TOWAIT:			// ATTENTION: any new command must be also added to method 'readRequests'
					case KW_WAIT: {

						BLOCK_WHILE_STAT_REGIME

						if (kw_id == KW_OR || kw_id == KW_ADD) {
							kw_id = KW_TOWAIT;
						}

						if (kw_id == KW_RECV) {
							kw_id = KW_WAIT;
						}

						if (reg == SR_SNIFFER) {

							throw new Exception("command is not allowed while working in this regime");
						}

						if (reg == SR_GEN) {

							if (kw_id != KW_WAITALL && kw_id != KW_SENDWAITOTHER) {

								prepare_packet();
								readRequests(kw_id);
							}

							if (kw_id == KW_SENDWAIT || kw_id == KW_SENDWAITOTHER) {

								ras -> pauseTrace();
								sendCommand(KW_SEND);
							}

							if (kw_id == KW_SENDWAIT || kw_id == KW_WAIT || kw_id == KW_WAITALL || kw_id == KW_SENDWAITOTHER) {

								if (!ras -> quietMode) {

									if (kw_id != KW_WAITALL) {

										if (nameOfCurrentPacket.size() == 0) {

											printf("Waiting packet on line %i...", text -> getLineNumber());
										}
										else
											printf("Waiting %s...", !nameOfCurrentPacket);
									}
									else {

										printf("Waiting packets...");
									}
								}

								fflush(stdout);

								if (kw_id != KW_WAITALL && kw_id != KW_SENDWAITOTHER) { // it's logical that KW_WAITALL doesn't start a new packet

								  newpac();
								}

								// starts the waiting

								UInt n = numIterations;
                        numIterations = 1;
								cycleWasBefore = false;
								for (UInt i = 0; i < n && !needBreak; i++) {

									ras -> waitAnyFirstPacket(getMainInterfaceNum(), timeoutForWaitCommand, i != n - 1, true);
								}
							}
							else {

							   newpac();
							}
						}

						break;
					}

               case KW_OPEN: {
                  MessageString type;
                  MessageString name;
                  readString(&type);
                  readString(&name);
						try
						{
							setMainInterfaceNum(MAIN_INTERFACE_NOT_SET);
							dev -> openInterface(type, name);
							mainInterfaceNum = dev -> getInterfaceNumberByName(name, true);
							setMainInterfaceNum(mainInterfaceNum);
							ras -> setNameLastReceivedPacket("ok");
						}
						catch (SocketInterface :: ConnectionFailedException* e) {
							ras -> setNameLastReceivedPacket("error");
							if (!ras -> quietMode) printf("%s\n", e -> get_message());
							delete e;
						}
						catch (SocketInterface :: ConnectionTimeoutException* e) {
							ras -> setNameLastReceivedPacket("timeout");
							if (!ras -> quietMode) printf("%s\n", e -> get_message());
							delete e;
						}
                  break;
               }

               case KW_CLOSE: {
                  MessageString name;
                  readString(&name);
                  uint n = dev -> closeInterface(name);
						// TODO: numbers of interfaces in requests are not shifted after this
						if ((int)n == mainInterfaceNum) {
							setMainInterfaceNum(MAIN_INTERFACE_NOT_SET);
						}
						else {
							if (mainInterfaceNum > (int)n) {
								mainInterfaceNum--;
							}
						}
                  break;
               }

					case KW_DEVICES: {

						UInt com_line_num = text -> getLineNumber();

                  // NOTE: if reg == SR_STAT then devices must be also open, otherwise there will be problems with unique names

                  if (fastTestAlreadyProccessed && reg == SR_GEN)

                     // this command will be ignored in generation regime after gathering packets info in stat regime

                     break;

						ras -> stopTrace();
						dev -> release();

                  //globalDevice = Null;

                  // reads the type of device
                  MessageString devName;

                  try
                  {
                     read_word(devName, true);

//                     if (word == "eth") {
//
//                        globalDevice = &globalEthernetDevice;
//                     }
//                     if (word == "ip") {
//
//                        globalDevice = &globalIPDevice;
//                     }
//                     if (word == "tcp") {
//
//                        globalDevice = &globalTCPDevice;
//                     }
//
//                     if (globalDevice == Null) {
//
//                        throw new Exception("given '%s', but expected the type of device - eth, ip, tcp.", !word);
//                     }
                  }

                  ADD_TO_ERROR_DESCRIPTION("reading the type of device");

						// reads interface's names

						text -> storeCurrentPosition();

						readString(&word);

						do {

							if (!word.size()) break;

							   // opens interface

                     dev -> openInterface(devName, word);

							text -> storeCurrentPosition();
							read_word(word);
						}
						while (text -> getLineNumber() == com_line_num);    // until next line

						if (text -> getLineNumber() != com_line_num)
							text -> restoreKeptPosition();

                  set_device(dev, 0);  // buf must be recteated corresponding to new type of device
                  convtest.device = dev;
                  ras -> set_device(dev);

						//buf -> newset();

						ras -> startConcurrentSniffersOnInterfaces();

						mysleep(PAUSE_BEFOR_GENERATING);

						break;
					}

					case KW_REP: {

						int num;

						try
						{
							readValue(&word);
							num = (UInt)word.getNumber(true, true);
						}
						ADD_TO_ERROR_DESCRIPTION("reading the number of seriated generation for current packet");

						numberOfGenerations = num;
						break;
					}

					case KW_INCLUDE: {

						MessageString nameIncludedFile;

						try
						{
							//readString(&nameIncludedFile, true);	// dont use, some problems occur
							read_word(nameIncludedFile, true, false);


							putValuesInMessage(&nameIncludedFile);
						}
						ADD_TO_ERROR_DESCRIPTION("reading the name of file to include");

						processIncludeCommand(nameIncludedFile);

						break;
					}

					case KW_SEND:   // simply sends

					case KW_SENDA:  // first request for packet is specified by command itself
					case KW_SENDD:
					case KW_BLOCK:
					case KW_ACCEPT:
					case KW_ANY:

						sendCommand(kw_id);
						newpac();
						break;

					case KW_DEFAULTS:

						ras -> setNoInitDefaults();
						readRequests(kw_id);
						break;

					case KW_INC:

						enableAutoincrement();
						break;

					case KW_CLEAR_MASK:

						ADDTOLOG1("Script :: run -- KW_RESET_MAS");

         			buf -> clearMask();
						break;

					case KW_CLEAR_HISTORY:

						buf -> clear_history();
						break;

					case KW_PAUSE: {

						u_int pause = 0;

						try
						{
							read_word(word, true);
							pause = (UInt)word.getNumber(true, true);
						}
						ADD_TO_ERROR_DESCRIPTION("reading the duration of pause (in milliseconds)");

						if (reg == SR_GEN)
							mysleep(pause);

						break;
					}

					default:

						throw new Exception("key word '%s' is not valid in current context", key_words[kw_id].keyword);
				}

				// reads ) after parameters

				text -> storeCurrentPosition();
				read_word(w1);
				if (w1 != ")") {

					if (bracketWasTyped)
						throw new Exception("the match ) is missing");
					text -> restoreKeptPosition();
				}
				else {

					if (!bracketWasTyped)
						throw new Exception("unexpected ), there is no corresponding (");
				}
			}
			}
			catch (Exception* e) {

				if (kw_id != -1) e -> add("command %s (parameters %s)", key_words[kw_id].keyword, key_words[kw_id].parameterssdf);
				throw;
			}

			if (cycleWasBefore && kw_id != KW_CYC) {
				throw new Exception("unexpected token '%s' after %s command, it can be followed only by restricted set of commands", !word, key_words[KW_CYC].keyword);
			}

			if (kw_id != -1) // if the word is command
				continue;

			// WORD IS NOT COMMAND

         if (valueType) {
            try
            {
               MessageString name;
               MessageString word;
               readNameEntity(&name, true, SE_VARIABLE);
               text -> nextWord(word, true);
               if (word != "=") {
                  throw new Exception("found '%s' but = expected followed by initial value for variable", !word);
               }

               FieldValue val(valueType);
               try
               {
                  readEntity(&word, false, true, QP_NOT_PROCESS_QUOTES, false);
                  val.readValue(!word, DefSize :: FOR_VARIABLE);
               }
               ADD_TO_ERROR_DESCRIPTION("reading the initial value for variable");

               FieldVariableValue v(name, val, 0, false);
               variables.addValue(v);
            }
            ADD_TO_ERROR_DESCRIPTION("creating variable");
            continue;
         }

         if (comProcessor) {
            try
            {
               comProcessor -> process(word, *this);
					continue;
            }
            catch (Exception* e) {
               e -> add("command %s (parameters %s)", !word, comProcessor -> getParameters(word).c_str());
               throw;
            }
         }


			if (fieldParameters != Null) {

				// processes name of field

				try
				{
					processFieldOcc(*fieldParameters);
				}
				ADD_TO_ERROR_DESCRIPTION2("reading value for field '%s'", !word);
				continue;
			}

			// processes variable assignment	or modification

			if (foundVariable) {

				MessageString word;
				bool addition = false;
				bool subtraction = false;

				try
				{

					try
					{
						readValue(&word);
						if (word == "=") {

							readValue(&word);
						}
						else {

							// addition specified

							if (word == "+=") {

								addition = true;
							}
							else {

								// subtraction specified

								if (word == "-=") {

									subtraction = true;
								}
							}
						}
					}
					ADD_TO_ERROR_DESCRIPTION("reading the new value for variable");

					if (!addition && !subtraction) {

						// reads new value

						try
						{
							foundVariable -> getValue().readValue(!word, DefSize :: FOR_VARIABLE);
						}
						ADD_TO_ERROR_DESCRIPTION("setting the given value");
					}
					else {

						// changes value

						readValue(&word);
						int numToAdd = (int)word.getNumber(true);

						if (subtraction) numToAdd = -numToAdd;
						foundVariable -> getValue().changeValue(numToAdd);
					}

					continue;
				}
				ADD_TO_ERROR_DESCRIPTION("variable assignment");
			}


			if (word[0] == '.') {

				// processes new field's definition

				MessageString nameOfNewField = word;

				nameOfNewField.erase(0, 1);

				searchEntity(&nameOfNewField, QP_NOT_PROCESS_QUOTES, true, true, false, SE_FIELD);

				try
				{
					processFieldDefinition(!word);
				}
				ADD_TO_ERROR_DESCRIPTION("defining a new field (as the word begins from .)");

				continue;
			}

			// processes name of included file

			MessageString full_path;

			includePaths.search(full_path, !word);
			if (full_path.size() != 0) {

				// processes included file

				processFile(!full_path);

			}
			else {

				// unknown word

				throw new Exception("'%s' - unknown word : expected command, name of field, variable, file or value's type", !word);
			}

		}  // main cycle

		if (textToProcess) text = lastText;
	}

	ADD_TO_ERROR_DESCRIPTION3("file '%s', line %i", !text -> getNameSource(), text -> getLineNumber());
}


void Script :: processElse(bool isProcess) {
	// processes ELSE block

	text -> storeCurrentPosition();
	MessageString val1;
	read_word(val1, false, false);
	if (val1 == "else") {

		try
		{
			read_word(val1, true, false);
			if (val1 != key_words[KW_START_BLOCK].keyword)
				throw new Exception("given '%s', but after \"else\" the start of new script block expected", !val1);

			runBlock(isProcess);
		}
		ADD_TO_ERROR_DESCRIPTION("processing the ELSE block");
	}
	else
		text -> restoreKeptPosition();
}


void Script :: processFile(const char* filename) throw(Exception*) {

	StresstestTextBuffer* lastText = text;

	if (needBreak) return;

	StresstestTextBuffer newText;
	text = &newText;

	// determines the name of folder for file (from the path to file) and adds to 'paths'

	MessageString fullPath;
	includePaths.search(fullPath, filename);
	if (fullPath.size() == 0) fullPath = filename;

	size_t res = fullPath.rfind("/");
	if (res == string :: npos)
		res = fullPath.rfind("\\");

	if (res != string :: npos) {

		MessageString folderPath;
		folderPath.assign(!fullPath, res);
		includePaths.add_path(&folderPath);
	}

	// reads file

	text -> readFile(!fullPath);

	// processes file's content

	try {
		run();
	}
	catch (ReturnException* e) {
		text = lastText;
		delete e;
	}
	catch (Exception* e) {
		text = lastText;
		throw e;
	}
	text = lastText;
}

MessageString& Script :: read_word(MessageString& word, bool failOnEmptyWord, bool removeEnclosingCommas) throw(Exception*) {

	text -> nextWord(word, failOnEmptyWord);

	const char* foundValue = globalDefines.search_value(!word);
	if (foundValue) {
      word = foundValue;
      putValuesInMessage(&word);
   }

	if (removeEnclosingCommas)
		StresstestTextBuffer :: removeEnclosingCommas(&word);

	return word;
}


void Script :: processFieldDefinition(const char* fieldName) {

	int offset;
	MessageString valueString;
	//const char* foundValue;
	const FieldMask* mask;

	ADDTOLOG2("Script :: processFieldDefinition -- start, fieldName = %s", fieldName);

	check(fieldName[0]);

	mask = fields.getmask();
	offset = fields.get_def_offset();

	// reads word

	read_word(valueString, true, false);

	putValuesInMessage(&valueString);

	searchEntity(&valueString, QP_NOT_PROCESS_QUOTES, true);

	// reads value with undefined type

   RefHolder<FieldValue> valueToWrite;
	text -> readValueUndefinedType(valueToWrite, !valueString, true); // check for correctness will be performed in searchEntity

	fields.addfield(fieldName + 1, buf -> getPos(), valueToWrite.ref() -> getType(), valueToWrite.ref() -> getSize(), &(text -> getLastComments()));

	text -> clearLastComments();

	// fills packet's buffer

	CommonField f(fields, fieldName + 1);
	f.setValue(*valueToWrite.ref());
	buf -> setFieldValue(f, true);

//	delete valueToWrite;
}


void Script :: addPacketToRas(int num, Request req, int interfaceNum, int line_number) {

	MessageString nameOfPacket = nameOfCurrentPacket;
	bool isNameGiven = true;
	if (nameOfCurrentPacket.size() == 0) {

		isNameGiven = false;
		nameOfPacket.resize(50 + text -> getShortNameSource().size());
		nameOfPacket.resize(sprintf((char*)nameOfPacket.c_str(), "Packet on line %i (%s)", line_number, !text -> getShortNameSource()));
	}

	boolean b = (outputMessageForCurrentPacket.size() == 0 || outputMessageForCurrentPacket == "\'\'");

	ras -> addPacket(num, getMainInterfaceNum(), req, interfaceNum,
		numberOfGenerations, buf -> getPacketSpecial(), &nameOfPacket, !b ? &outputMessageForCurrentPacket : 0, isNameGiven);
}


void Script :: processVarCommand(bool* bracketWasTyped) {

	MessageString fieldName;
	MessageString varName;
	MessageString varValue;
	MessageString varType;

	CommonField* commonField;

	ADDTOLOG1("Script :: processVarCommand -- start");

	try
	{
		readNameEntity(&varName, true, SE_VARIABLE);
	}
	ADD_TO_ERROR_DESCRIPTION("reading the name of variable");

	try
	{
		readNameEntity(&fieldName);

		ADDTOLOG3("Script :: processVarCommand -- fieldName = %s, varName = %s", !fieldName, !varName);

		commonField = new CommonField(fields, !fieldName);
	}
	ADD_TO_ERROR_DESCRIPTION("reading the name of field");

	try
	{
		readValue(&varValue, true);
		commonField -> readValue(!varValue);
	}
	ADD_TO_ERROR_DESCRIPTION("reading the initial value for variable");

	bool autoSet = false;

	try
	{
		read_word(varType, true, false);

		if (varType == ")") {

			if (!(*bracketWasTyped))
				throw new Exception("unexpected bracket");

			*bracketWasTyped = false;
		}
		else {

			if (varType == "autoset") autoSet = true;
			else {

				if (varType != "static")
					throw new Exception("given '%s', but expected the type of variable (static or autoset)", !varType);
			}
		}
	}
	ADD_TO_ERROR_DESCRIPTION("reading the type of variable");

   FieldVariableValue v(varName, commonField -> getValue(), &(commonField -> getFieldInfo()), autoSet);
	variables.addValue(v);

	delete commonField;

	ADDTOLOG1("Script :: processVarCommand -- end");
}


void Script :: processIncludeCommand(MessageString& nameIncludedFile) {

	MessageString fullNameIncludedFile;

	StresstestTextBuffer :: removeEnclosingCommas(&nameIncludedFile);

	// reads file's name

	fullNameIncludedFile = nameIncludedFile;

	// resolves file's name (searches it)

	includePaths.search(fullNameIncludedFile, !nameIncludedFile);
	if (!fullNameIncludedFile.size()) {

		throw new Exception("file '%s' not found : make sure that you correctly install program or give correct paths with -I option ",!nameIncludedFile);
	}

	// processes text

	processFile(!fullNameIncludedFile);
}


void Script :: performAutoincrement() {

	if (!autoIncrementedField) return;

	autoIncrementedField -> changeValue(1);
	buf -> setFieldValue(*autoIncrementedField, false);
}


void Script :: processDefineCommand(bool global) {

	MessageString name;
	MessageString val;

	// reads the first name - the name while will be substituted

	try
	{
		text -> nextWord(name, true);		  // only this function, don't use Script :: read_word or any higher level function
														  // otherwise already existing substitutions will be performed while reading this name
		if (is_keyword(!name) != NOT_KEY_WORD)
			throw new Exception("key word is not allowed");
	}
	ADD_TO_ERROR_DESCRIPTION("reading the first name which will be replaced");

	// reads the second name - the name which will be inserted

	try
	{
		readEntity(&val, false, true, QP_NOT_PROCESS_QUOTES, true, false, false, SE_NOT_DEFINED);
	}
	ADD_TO_ERROR_DESCRIPTION("reading the second name by which the first will be replaced");

	if (!global) {

		if (globalDefines.search_value(!name) != Null) {

			throw new Exception("substitution with the same name already exist");
		}
		defines.addfield(!name, !val);
	}
	else {

		if (defines.search_value(!name) != Null) {

			throw new Exception("substitution with the same name already exist");
		}
		globalDefines.addfield(!name, !val);
	}
}


void Script :: sendCommand(int keywordID) {

	ADDTOLOG2("Script :: sendCommand, keywordID = %s", key_words[keywordID]);

	// forbids using request qualifier as command if not FASTTEST and not SR_STAT

	if ((keywordID == KW_SENDA || keywordID == KW_SENDD || keywordID == KW_BLOCK || keywordID == KW_ACCEPT)
		&& !fastTestAlreadyProccessed && reg != SR_STAT)

		throw new Exception("processing '%s' : request specification may only follow some command or fast test must be enabled (command %s)", key_words[keywordID].keyword, key_words[KW_FASTTEST].keyword);

	prepare_packet();	// don't remove it (for SR_STAT or SR_SNIFFER regimes)

	if (reg == SR_GEN) {

		int i;

		// generations cycle

		for (i = 0; i < numberOfGenerations && !needBreak; i++) {

			if (i && autoIncrementedField) {

				// if value for some field is incremented then we must prepare_packet every time (except the first)

				prepare_packet();
			}

			if (!dev -> numOpenedInterfaces() && dev -> getInterface(getMainInterfaceNum()) -> getDevice()  -> gettype() != IPDevice :: name) {

				 // no opened interfaces
             throw new Exception("sending packet : no interface opened (use option -d or %s command)", key_words[KW_DEVICES].keyword);
         }

			buf -> send(this);  // one generation

			if (numberOfGenerations > 1 && interval != 0)
				mysleep(interval);

			performAutoincrement();
		}

		// displays message

		if (!ras -> quietMode) {

			if (nameOfCurrentPacket.size() == 0) {

				printf("Was generated packet on line %i (%i times), user size = %i\n", text -> getLineNumber(), i,
					buf -> getCurrentSize() - buf -> getinitpos());
			}
			else

				printf("Was generated %s (%i times), user size = %i\n", !nameOfCurrentPacket, i,
					buf -> getCurrentSize() - buf -> getinitpos());
		}
	}

	// reads requests after the command

	readRequests(keywordID);
}



void Script :: readRequests(int firstKeyWordID) {

	MessageString word;
	int nextRequest;
	bool isWaitCommand = false;

	u_int bline_number = text -> getLineNumber();  // before reading requests stores the line's number

	if (firstKeyWordID == KW_SENDWAIT || firstKeyWordID == KW_WAIT || firstKeyWordID == KW_TOWAIT || firstKeyWordID == KW_WAITALL || firstKeyWordID == KW_SENDWAITOTHER)
		isWaitCommand = true;

	if (firstKeyWordID == KW_DEFAULTS) {

		// DEFAULTS command
		// fills default requests by RAS_NOINIT value

		for (UInt i = 0; i < MAX_NUM_PORTS; i++) {

			ras -> defaultRequests[i] = RAS_NOINIT;
		}
	}

	// reads request's specifications until the first word which is not request specification

	int i;
	for (i = 0; i < MAX_NUM_PORTS - 1; i++) {  // "MAX_NUM_PORTS - 1": see 'interfaceNum' initialization

		text -> storeCurrentPosition();

		if (
				i == 0
				&&
				(firstKeyWordID == KW_ACCEPT || firstKeyWordID == KW_BLOCK || firstKeyWordID == KW_SENDA
					|| firstKeyWordID == KW_SENDD || firstKeyWordID == KW_ANY)
			) {

			// the firstKeyWordID defines the first request itself

			nextRequest = firstKeyWordID;

		} else {

			// reads request specification

			read_word(word);
			nextRequest = is_keyword(!word);
		}

		// translates similar codes to only two codes

		if (nextRequest == KW_ACCEPT) nextRequest = KW_SENDA;
		if (nextRequest == KW_BLOCK) nextRequest = KW_SENDD;


		if (nextRequest != KW_SENDA && nextRequest != KW_SENDD && nextRequest != KW_ANY
			&& (nextRequest != KW_REVERS || firstKeyWordID != KW_DEFAULTS)
			) {

			// the word is not request's specification

			text -> restoreKeptPosition();

			if (i == 0) {

				// there are no requests, but the packet must be added (default requests will be set)

				if (firstKeyWordID != KW_DEFAULTS) {

					if (((reg == SR_STAT || reg == SR_SNIFFER)) || isWaitCommand)
						addPacketToRas(SER_NEW_PACKET, ras -> defaultRequests[0], 0, bline_number);
				}
			}

			break;
		}

		// while stas regime requests will be shifted relative to interfaces
		// the request for first interface will stay uninitialized

		int interfaceNum = (reg == SR_STAT) ? i + 1 : i;

		if (extendedRegime) {

			// extended regime has specified
			// reads the unique name of interface

			try
			{
				MessageString s;
            read_word(s, true);
				interfaceNum = ras -> getInterfaceNumByName(s, true);
			}

			ADD_TO_ERROR_DESCRIPTION("reading the unique name of interface after request");
		}

		if (firstKeyWordID != KW_DEFAULTS)

			if (ras -> defaultRequests[interfaceNum] == RAS_REVERS) {

				// revers request has specified

				if (nextRequest == KW_SENDA) nextRequest = KW_SENDD;
				else if (nextRequest == KW_SENDD)  nextRequest = KW_SENDA;
			}

		Request request = RAS_NOINIT;

		// translates key word's code to request's codes

		switch (nextRequest) {

			case KW_SENDA:

				request = RAS_ACCEPT;
				break;

			case KW_SENDD:

				request = RAS_DROP;
				break;

			case KW_ANY:

				request = RAS_ANY;
				break;

			case KW_REVERS:

				request = RAS_REVERS;
				break;

			default: Test();
		}

		if (firstKeyWordID != KW_DEFAULTS) {

			// adds the packet
			// while SR_GEN regime if it's not wait command then the packet will not be added

			if (reg == SR_STAT || reg == SR_SNIFFER || isWaitCommand)
				addPacketToRas(i ? SER_LAST_PACKET : SER_NEW_PACKET, request, interfaceNum, bline_number);
		}
		else {

			// sets default request for interface

			ras -> defaultRequests[interfaceNum] = request;
		}
	}

	if (i == MAX_NUM_PORTS - 1) {

		throw new Exception("too many request's specifications");
	}
}


void Script :: makeSystemCall(const MessageString& command) {

	#ifdef WIN32
	STARTUPINFO stinfo;
	PROCESS_INFORMATION prinfo;
	memset(&stinfo, 0, sizeof(stinfo));
	stinfo.cb = sizeof(stinfo);
	memset(&prinfo, 0, sizeof(prinfo));

	if (!CreateProcess(
		NULL,
		(LPSTR)!command,
		NULL,
		NULL,
		false,
		NORMAL_PRIORITY_CLASS | CREATE_DEFAULT_ERROR_MODE | CREATE_NEW_PROCESS_GROUP,
		NULL,
		NULL,
		&stinfo,
		&prinfo
		)) {

			printf("Warning: running application %s : %s\n", !command, winerror());
	}
	resultLastSystemCall = 0;
	#else
	if (-1 == (resultLastSystemCall = system(!command))) {

		printf("\nwarning: error while system call (%s)\n", !command);
	}
	resultLastSystemCall >>= 8;	// 'system' returns value shifted by 8 bits to the left
	#endif
}


TypeCompareField Script :: isCompareQualifier(const MessageString& word) {

	check(TCF_NUM_TYPES == 6);

	if (word == "=") return TCF_EQUAL;
	if (word == "==") return TCF_EQUAL;
	if (word == "!=") return TCF_NOT_EQUAL;
	if (word == ">") return TCF_GREATER;
	if (word == "<") return TCF_LESS;
	if (word == ">=") return TCF_GREATER_EQUAL;
	if (word == "<=") return TCF_LESS_EQUAL;

	return TCF_UNDEFINED;
}


void Script :: processFieldOcc(const FieldInfo& fieldParameters) {

	ADDTOLOG2("Script :: processFieldOcc, lineNumber = %i", text -> getLineNumber());

	TypeCompareField typeCompareField = TCF_EQUAL;
	//UInt sizeField;
	RefHolder<DBuffer> valueToWrite;
	//Field fieldParameters;
	bool clearMaskValue = false;

	// searches name of field (must be found)

	//check(fields.search_field(fieldName, &fieldParameters));

	//sizeField = f.getSizeField();

	//ADDTOLOG4("Script :: processFieldOcc -- sizeField = %i, pos = %i, offset = %i", sizeField, fieldParameters.pos, fieldParameters.offset);



	// READS VALUE	(more generally condition specification)

	MessageString value_word;

	try
	{
		// reads the next word

		read_word(value_word, true);

		if ((typeCompareField = isCompareQualifier(value_word)) != TCF_UNDEFINED) {

			// the read word is compare qualifier

			read_word(value_word, true);
		}
		else

			// no compare qualifier

			typeCompareField = TCF_EQUAL;
	}
	ADD_TO_ERROR_DESCRIPTION("reading value of field");

	if (value_word == key_words[KW_ANY].keyword) {

		// specified "any" as value for field

		ADDTOLOG1("Script :: processFieldOcc -- empty value");
		clearMaskValue = true;
	}

	// resolves names of fields, variables, substitutionsOfValues

   putValuesInMessage(&value_word);

	searchEntity(&value_word, QP_NOT_PROCESS_QUOTES, true, false, false, SE_FIELD_VALUE);

	if (autocalcManager -> searchValue(!value_word) != 0) {

		// processes auto calculated value

      if (fieldParameters.getSize().isUndefined()) {

			throw new Exception("trying to apply some auto calculated value to the field with undefined size");
		}

		autocalcManager -> setValueAsActive(!value_word, fieldParameters);
		buf -> setpos(fieldParameters.getPos() + fieldParameters.getSize().num());

		return;
	}
	else {

		// reads real value

		ADDTOLOG1("Script :: processFieldOcc -- reading some value");

		if (KW_RAND_VALUE == is_keyword(!value_word)) {

			// random value

         if (fieldParameters.getSize().isUndefined()) {

            throw new Exception("trying to apply random value to the field with undefined size");
         }

         valueToWrite.set(new DBuffer());
         UInt sizeField = fieldParameters.getSize().num();
         for (UInt i = 0; i < sizeField; i++) {

            valueToWrite.ref() -> setByte(i, (u_char)((float)rand()*255/RAND_MAX));
         }

		}  else  {

			// common value

			if (!clearMaskValue) {

				ADDTOLOG2("Script :: processFieldOcc -- reading value = %s", !value_word);

            FieldValue* val = new FieldValue(&fieldParameters.getType());
            val -> readValue(!value_word, fieldParameters.getSize());
            valueToWrite.set(val);
			}
		}
	}

	if (!valueToWrite.ref()) valueToWrite.set(new DBuffer());

	ADDTOLOG2("Script :: processFieldOcc -- size of value = %i", valueToWrite.ref() -> getSize());

	// checks the correspondence of field's size and value's size

	if (!clearMaskValue && !fieldParameters.getSize().isPermitted(valueToWrite.ref() -> getSize())) {

		throw new Exception("the size of field (%i) is different from the size of value = %i", fieldParameters.getSize().num(), valueToWrite.ref() -> getSize());
	}

	// writes read value to packet's buffer
   CommonField f(fieldParameters);
	if (!clearMaskValue) f.setValue(*valueToWrite.ref());

	if (typeCompareField == TCF_EQUAL && !clearMaskValue) {

		// sets byte pointer to the position of field

		buf -> setpos(f.getPositionInPacket());

		// writes the value

		buf -> setFieldValue(f, false);

		// works with autoIncrementedField

		if (autoincrementEnabled && !autoincrementedFieldAssigned) {

			if (autoIncrementedField) delete autoIncrementedField;
			autoIncrementedField = new CommonField(fieldParameters);

			autoIncrementedField -> setValue(*valueToWrite.ref());

			autoincrementedFieldAssigned = true;
		}
	}
	else {

		// adding the special condition  (not equality, greater than and others)

		if (!clearMaskValue) {

			buf -> addSpecialCondition(f, typeCompareField);
		}
		else {

			// processes the 'any' value

			buf -> excludeFromMask(f);
		}
	}
}



void Script :: searchEntity(MessageString* name, QuotesProccessing quotesProccessing, bool withTypeInfo, bool doNotResolve, bool checkNotResolvedName, TypeOfEntity typeOfEntity) {

	FieldVariableValue* var;
	MessageString initName = *name;
	bool found = false;

	const char* s;

	if (!doNotResolve) {

		// searches amoung some key words - special values

		if (!found && *name == key_words[KW_CURTIME].keyword) {

         ostringstream s;
         s.fill('0');

	#ifdef WIN32
			SYSTEMTIME systemTime;
			GetLocalTime(&systemTime);

//			name -> resize(30);
//			name -> resize(snprintf((char*)name -> c_str(), 30, "%02u:%02u:%02u.%03u", systemTime.wHour, systemTime.wMinute, systemTime.wSecond, systemTime.wMilliseconds));

         s.width(2);
         s << systemTime.wHour << ":";
         s.width(2);
         s << systemTime.wMinute << ":";
         s.width(2);
         s << systemTime.wSecond << ":";
         s.width(2);
         s << systemTime.wMilliseconds;

	#else
			time_t t;
			struct tm* tmp;
			struct timeval tt;

			gettimeofday(&tt, 0);

			t = time(0);
			tmp = localtime(&t);
			systemCheck(t != 0);
//			name -> resize(30);
//			name -> resize(sprintf((char*)name -> c_str(), "%02u:%02u:%02u.%06u", tmp -> tm_hour, tmp -> tm_min, tmp -> tm_sec, tt.tv_usec));
         s.width(2);
         s << tmp -> tm_hour << ":";
         s.width(2);
         s << tmp -> tm_min << ":";
         s.width(2);
         s << tmp -> tm_sec << ":";
         s.width(2);
         s << tt.tv_usec;
	#endif
         *name = s.str();
		}

		if (!found && *name == key_words[KW_CALLRES].keyword) {

			ostringstream s;
         s << (int)resultLastSystemCall;
			*name = s.str();

			found = true;
		}

		if (!found && *name == key_words[KW_LASTRES].keyword) {

			ostringstream s;
         s << (int)ras -> getLastStatus();
			*name = s.str();

			found = true;
		}

		if (!found && *name == key_words[KW_GOTORES].keyword) {

			if (dataWasFound)
				*name = "1";
			else
				*name = "0";

			found = true;
		}

		if (!found && *name == key_words[KW_GETCURPOS].keyword) {

			ostringstream s;
         s << (UInt)buf -> getPos();
			*name = s.str();

			found = true;
		}

		if (!found && *name == key_words[KW_GETCURSIZE].keyword) {

         ostringstream s;
         s << (UInt)buf -> getCurrentSize();
			*name = s.str();

			found = true;
		}

      if (!found && *name == key_words[KW_RAND_VALUE].keyword && typeOfEntity != SE_FIELD_VALUE) {

         ostringstream s;
         s << (u_int)((float)rand()*255/RAND_MAX);
			*name = s.str();

			found = true;
		}

	}

	bool entityAlreadyExists = false;

	// searches amoung defines

	UInt numRecord;
	if (!found && (s = defines.search_value(!(*name)))) {

		*name = s;
		//if (!withTypeInfo) StresstestTextBuffer :: removeEnclosingCommas(name);

		found = true;

		if (typeOfEntity != SE_SUBSTITUTION) {
			entityAlreadyExists = true;
		}

      // TODO[at] fix infinite recursive call error when 'gdef hh hh'
      searchEntity(name, QP_NOT_PROCESS_QUOTES, true, false, false );

      putValuesInMessage(name);

	}

	// searches amoung global defines

	if (!found && (s = globalDefines.search_value(!(*name)))) {

		*name = s;
		//if (!withTypeInfo) StresstestTextBuffer :: removeEnclosingCommas(name);

		found = true;

		if (typeOfEntity != SE_GLOBAL_SUBSTITUTION) {

			entityAlreadyExists = true;
		}

      searchEntity(name, QP_NOT_PROCESS_QUOTES, true, false, false );

      putValuesInMessage(name);

	}

//   if (found && )

	// searches amoung variables

	var = variables.getVariable(!(*name), false, &numRecord);
	if (!found && var) {

		*name = var -> getValue().getValueString(withTypeInfo);

		found = true;

		if (typeOfEntity != SE_VARIABLE) {
			entityAlreadyExists = true;
		}
	}

	// searches amoung field's names

	if (!found && fields.getField(*name, &numRecord)) {

		if (!doNotResolve) {

			CommonField var(fields, !(*name));

			// retrieve the value from packet content
			if (var.setByPacket(!(buf -> getPacketSpecial() -> getContentOfPacket()), buf -> getCurrentSize()) != ICR_OK) {

				throw new Exception("unable to get value for field '%s', packet's size = %i, may be it's less than field's position + field's size", !(*name), buf -> getCurrentSize());
			}
			*name = var.getValueString(withTypeInfo);

			ADDTOLOG2("value of field=%s",name -> c_str());
		}

		found = true;

		if (typeOfEntity == SE_FIELD)

			fields.deleteRecord(numRecord);

		else {

			entityAlreadyExists = true;
		}
	}

	if (entityAlreadyExists
		 && (typeOfEntity == SE_FIELD || typeOfEntity == SE_GLOBAL_SUBSTITUTION
		    || typeOfEntity == SE_SUBSTITUTION || typeOfEntity == SE_VARIABLE
			 )
		) {

		throw new Exception("entity with name '%s' already exists", !initName);
	}

   if (!found) {
      if (quotesProccessing == QP_REMOVE_REQUIRED_QUOTES && !StresstestTextBuffer :: isQuoted(*name)) {
         throw new Exception(MUST_BE_QUOTED_ERROR);
      }
   }

	if (!found && checkNotResolvedName) {

		bool thisIsNumber = true;

		// checks is the string number (for numbers 'readValueUndefinedType' assumes 1 byte size,
		//										  for big numbers this may cause error, so if it is any number => dont call readValueUndefinedType)

		try
		{
			name -> getNumber(true, false);
		}
		catch (Exception* e) {

			delete e;
			thisIsNumber = false;
		}

		// checks does the string correspond any value's type

		if (!thisIsNumber) {

			try
			{
            RefHolder<FieldValue> h;
				text -> readValueUndefinedType(h, !(*name));
			}
			ADD_TO_ERROR_DESCRIPTION(MUST_BE_QUOTED_ERROR);
		}
	}

	/*if (found && errorIfFound) {

		throw new Exception("entity with name '%s' already exists", !initName);
	}*/

	if (doNotResolve) *name = initName;
	if (quotesProccessing == QP_REMOVE_OPTIONAL_QUOTES || quotesProccessing == QP_REMOVE_REQUIRED_QUOTES)
		StresstestTextBuffer :: removeEnclosingCommas(name);
}



void Script :: processARepMakerCommand() {

	CommonField* field = Null;
	MessageString fieldName;
	MessageString value;

	try
	{
		read_word(fieldName, true, false);
		field = new CommonField(fields, !fieldName);
	}
	ADD_TO_ERROR_DESCRIPTION("reading the name of field for constraint");

	try
	{
		//read_word(value, true, true);
		//searchEntity(&value, true, false);
		convtest.processValueDefinition(this, field);
	}
	ADD_TO_ERROR_DESCRIPTION("reading the value of field");

	convtest.addARepMaker(*field);

	delete field;
}

void Script :: setMainInterfaceNum(int num) {

	mainInterfaceNum = num;
	if (num == MAIN_INTERFACE_NOT_SET) {
		ras -> setNoInitDefaults();
	}
	else {
		check(num < dev -> numOpenedInterfaces());
		ras -> setCommonDefaults(num);
		buf -> updateUponInterfaceChange(dev -> getInterface(num));
		fields.setPositionOfField(DATA_FIELD, dev -> getInterface(num) -> getDevice() -> getPositionDataBegins());
	}
}

void Script :: putValuesInMessage(MessageString* message) {

	MessageString resultMessage;
	MessageString nameOfItem;
	MessageString valueString;

   if (!StresstestTextBuffer :: isEnclosedInApostrophes(*message))
      return;

	uint si = 0;
	uint di = 0;
	for (; si < message -> size(); ) {

		if ((*message)[si] == '$') {

			uint posFirstDollar = si;
			si ++;
			for (; (*message)[si] != '$' && si < message -> size(); si++);

			if (si != message -> size() && si > posFirstDollar + 1) {

				//bool found = false;
				nameOfItem = *message;

				nameOfItem.erase(0, posFirstDollar + 1);
				nameOfItem.erase(si - posFirstDollar - 1, nameOfItem.size() - (si - posFirstDollar - 1));

				valueString = nameOfItem;

//				const char* c;
//				if ((c = globalDefines.search_value(!valueString))) {
//					valueString = c;
//               putValuesInMessage(&valueString);
//            }

				searchEntity(&valueString, QP_REMOVE_OPTIONAL_QUOTES, false);

				resultMessage.insert(di, valueString);
				di += valueString.size();

				si++;
				continue;
			}
			else {

				if ((*message)[si] != '$')
					si = posFirstDollar;
			}
		}

		resultMessage.resize(di + 1);
		resultMessage.at(di) = (*message)[si];
		si++;
		di++;
	}

	resultMessage.resize(di);
	*message = resultMessage;
}


const char* Script :: getKeyWord(int kwID) {

	return key_words[kwID].keyword;
}

int is_keyword(const char* word) {

   int i;
   for (i=0; key_words[i].keyword; i++)
      if (!strCaseCompare(key_words[i].keyword,word)) return i;

   return NOT_KEY_WORD;
}


void printKeyWordInfo(const MessageString& keyword) {

	for (UInt i = 0; key_words[i].keyword; i++) {

		if (keyword == "all" || keyword == key_words[i].keyword) {

			printf("%s\n", key_words[i].keyword);
			printf("   PARAMETERS: %s\n", key_words[i].parameterssdf);
			printf("   DESCRIPTION:\n%s\n", key_words[i].descriptionsdf);
			printf("\n");
		}
	}
}


int Script :: readEntity(MessageString* word,
   bool failOnKeyword,
   bool failOnEmptyWord, // true: if reads some key word then throws Exception
   QuotesProccessing quotesProccessing,
   bool doNotSearchEntity,  // true: doesnt attempt to make the substitution of entity's name by its value (for fields, variables and others)
   bool checkNotResolvedName, // see method searchEntity
   bool resolveRef,
   TypeOfEntity typeOfEntity // see searchEntity method
   ) {

   try
   {
   // reads word

   read_word(*word, failOnEmptyWord, false);

   /** searches found word amoung key words */

   int kwID = is_keyword(!(*word));

   /** inserts values in expandable string */

   if (resolveRef) putValuesInMessage(word);

   /** substitutes values for names of variables, fields and others */

   if (!doNotSearchEntity)
      searchEntity(word, quotesProccessing, true, false, checkNotResolvedName, typeOfEntity);
   else
      searchEntity(word, quotesProccessing, true, true, false, typeOfEntity);

   if (kwID != NOT_KEY_WORD && is_keyword(!(*word)) != NOT_KEY_WORD) {

      /** may throw Exception if found amoung key words */

      if (failOnKeyword) {

         throw new Exception("%s is key word, it cannot be used in current context", !(*word));
      }
   }

   return kwID;
   }
   ADD_TO_ERROR_DESCRIPTION2("value \"%s\"", !*word);
}

Substitutions :: Substitutions () {
}


void Substitutions :: addfield(const char* name, const char* value) {

	sharedAccessMutex.wait();

	try
	{
		//UInt numFoundRecord;
		SubstitutionInfo* found;
		if ((found = search(name)))
		{
			found -> val = value;
		}
		else
		{
			SubstitutionInfo si;
			si.val = value;
			si.name = name;
			this -> subs.push_back(si);
		}
	}

	ADD_TO_ERROR_DESCRIPTION("adding the new word replace");

	sharedAccessMutex.release();
}

SubstitutionInfo* Substitutions :: search(const char* name) {

	sharedAccessMutex.wait();

	for (int i = 0; i < subs.size(); i++) {
      if (!strCaseCompare(!(subs[i].name), name)) {
			return &subs[i];
      }
   }

	sharedAccessMutex.release();

   return 0;
}

const char* Substitutions :: search_value(const char* name) const {

	sharedAccessMutex.wait();

	vector<SubstitutionInfo>::const_iterator it = subs.begin();
	while (it != subs.end()) {

      if (!strCaseCompare(!(it -> name), name)) {

			return it -> val.c_str();
      }
		++it;
   }

	sharedAccessMutex.release();

   return 0;
}

int Script :: getMainInterfaceNum() {
   if (mainInterfaceNum == MAIN_INTERFACE_NOT_SET) {
      throw new Exception("main interface is not set : former main interface was closed probably or new one was unsuccessfully opened : use MI command to set main interface");
   }
   return mainInterfaceNum;
}
