#ifndef STRESSTEST_SCRIPT_H
#define STRESSTEST_SCRIPT_H

#include "stresstest.h"
#include "network.h"
#include "fields.h"
#include "pacbuf.h"
#include "stresstest_functs.h"
#include "reqandstat.h"
#include "paths.h"
#include "messagebuff.h"
#include "messagestring.h"
#include "fieldVariableValues.h"
#include "protocolsExpert.h"
#include "stresstestTextBuffer.h"
#include "convtest.h"

class Testing;

// work regimes for Script object

#define SR_NOINIT		0	  // not initialized
/**	generating packets mainly,
   and waiting some packets while using special commands
*/
#define SR_GEN  		1

/**
analysing the script,
and passing all defined packets to ReqAndStat object for further work,
the requests for packets correspond all interfaces except first
*/
#define SR_STAT 		2
/**
same as SR_STAT
but the requests for packets correspond all interfaces starting from first
*/
#define SR_SNIFFER 		3

enum TypeOfEntity {

	SE_NOT_DEFINED,
	SE_FIELD,
	SE_VARIABLE,
	SE_SUBSTITUTION,
	SE_GLOBAL_SUBSTITUTION,
	SE_FIELD_VALUE
};

enum QuotesProccessing {
   QP_NOT_PROCESS_QUOTES,
   QP_REMOVE_REQUIRED_QUOTES,
   QP_REMOVE_OPTIONAL_QUOTES
};

#define BLOCK_WHILE_STAT_REGIME if (reg == SR_STAT) { throw new Exception("command %s is not available while fast test",key_words[kw_id].keyword); }

#define NOT_KEY_WORD (-1)

struct KeyWordsInfo {

	const char* keyword;
	const char* parameterssdf;
	const char* descriptionsdf;

   //KeyWordsInfo(const char* s1, const char* s2, const char* s3) {

   //}
};

 /** enumeration of key words (ATTENTION: must correspond to key_words array) */
typedef enum {
	KW_SEND,
	KW_PAUSE,
	KW_BLOCK,
	KW_ACCEPT,
	KW_ANY,
	KW_REP,
	KW_SENDA,
	KW_SENDD,
	KW_CLEAR_MASK,
	KW_INC,
	KW_OFFSET,
	KW_DEFAULTS,
	KW_INCLUDE,
	KW_DEVICES,
	KW_WAIT,
	KW_EXIT,
	KW_PASS,
	KW_DEFINE,
	KW_MASK,
	KW_POS,
	KW_BACK,
	KW_CLEAR_HISTORY,
	KW_VAR,
	KW_NAME_OF_PACKET,
	KW_OUTPUT_MESSAGE,
	KW_EXTENDED,
	KW_MAIN_INTERFACE,
	KW_REVERS,
	KW_BEEP,
	KW_SAFETERM,
	KW_INTERVAL,
	KW_INCVAR,
	KW_TOWAIT,
	KW_GDEFINE,
	KW_TIMEOUT,
	KW_QUIET,
	KW_CYC,
	KW_SYSCALL,
	KW_NOTDOUBLEMES,
	KW_RAND_VALUE,
	KW_CAREFULWAIT,
	KW_OPENTRACE,
	KW_EP,
	KW_RUN,
	KW_WRITETRACE,
	KW_GETPAC,
	KW_SETPAC,
	KW_INSPAC,
	KW_DELPAC,
	KW_FULLMASK,
	KW_START_BLOCK,
	KW_END_BLOCK,
	KW_IFR,
	KW_PRINT,
	KW_FILTER,
	KW_UNFIX,
	KW_WAITALL,
	KW_CHTRACE,
	KW_COPYRECPACKET,
	KW_FASTTEST,
	KW_GETCH,
	KW_NUMRET,
	KW_RM,
	KW_ARM,
	KW_RANGE,
	KW_HELP,
	KW_TIMED,
	KW_DEFAULTTEST,
	KW_SETSIZE,
	KW_IF,
	KW_GETCURPOS,
	KW_GETCURSIZE,
	KW_GOTO,
	KW_GOTOB,
	KW_GOTORES,
	KW_SETPOS,
	KW_DECVAR,
   KW_BREAK,
	KW_RECV_POINT,
	KW_GEN,
	KW_FIRST,
	KW_SECOND,
	KW_CIEVE,
	KW_IFNDEF,
	KW_CALLRES,
	KW_MULVAR,
	KW_DIVVAR,
	KW_SENDWAIT,
	KW_NOTCOPYREC,
	KW_CLEARREG,
	KW_SHOWREP,
	KW_LASTRES,
	KW_CURTIME,
	KW_PRINTL,
	KW_FIXMASK,
	KW_UNFIXMASK,
	KW_LOADVAR,
	KW_WRITEVAR,
	KW_IFDEF,
	KW_PLAY,
	KW_NEWLINEIS,
	KW_SENDWAITOTHER,
   KW_OPEN,
   KW_CLOSE,
   KW_OR,
   KW_ADD,
   KW_RESET,
   KW_CLEAR,
   KW_RECV,
   KW_RETURN
}
KEY_WORD_ID;

/**
 * Processes a set of commands from script.
 * The class is responsible for correct reading the whole list of parameters from script after command name.
 * It receives the whole control over reading after one of its command is found in script.
 * See derived classes as examples.
 * @param command
 * @return
 */
class CommandsProcessor
{
public:
   /**
    * returns true if given command may be processed by this processor.
    * @param command
    * @return
    */
   virtual boolean isProcessCommand(const MessageString& command) = 0;
   /**
    * returns the description of parameters (printed for user)
    * @param command
    * @return
    */
   virtual MessageString getParameters(const MessageString& command) = 0;

   /**
    * processes command. this method may read from script until the list of command's parameters is finished.
    * after call the cursor must be set just after parameters list.
    * @param command
    * @param script
    */
   virtual void process(const MessageString& command, Script& script) = 0;
};

/**
 NOT_KEY_WORD - not key word,
 returns the index of a command or a key word by the given name (see enumeration KEY_WORD_ID)
*/
int is_keyword(const char* word);
void printKeyWordInfo(const MessageString& keyword = "all");


/**
 struct sibstitution (see command DEFINE,...)
 maps a name to a value
*/
struct SubstitutionInfo {

	/** name that will be sought in text */
	MessageString name;
	/** value that replaces the name */
	MessageString val;
};


/** Array of SubstitutionInfo */

class Substitutions
{

private:

	vector<SubstitutionInfo> subs;
	MyMutex sharedAccessMutex;

protected:

	/**
	 searchs
   returns NULL if not found
	*/
	SubstitutionInfo* search(
	  const char* name

	  ) ;

public:

  Substitutions();

  /** removes all */
  void clear() { sharedAccessMutex.wait(); subs.clear(); sharedAccessMutex.release(); }

  /**
   adds
   if substitution with such name is already exist then it will be deleted
  */
  void addfield(const char* name,
					const char* value
					);

	const char* search_value(const char* name) const;

};


/**********************************************************
***********************************************************
******************   Class  Script   **********************
***********************************************************
**********************************************************/

/**
	Class Script.

	The central class of stresstest program.
	Processes a test script.
	Script may be passed as a string or the name of a file may be specified.
	Coordinates the work of many other objects.
	References to other objects must be given in constructor.

*/
class Script {

#ifdef TEST_MODE

	friend class Testing;

#endif //TEST_MODE

	//friend class SequenceOfPackets;
	//friend class Convtest;

private:

   vector<CommandsProcessor*> commandProcessors;

   AutocalcManager* autocalcManager;

   /** field whose value will be incremented and inserted for each next packet
      while generating multiple packets (REP command)
   */
	CommonField* autoIncrementedField;

	/** current text */
	StresstestTextBuffer* text;

	/** true - regime of autoincrement has been enabled by command INC */
	bool autoincrementEnabled;

	/** true - the field which value must be autoincremented is already known */
	bool autoincrementedFieldAssigned;

	/** command TIMEOUT */
	UInt timeoutForWaitCommand;

	/** name of current packet, may be empty */
	MessageString nameOfCurrentPacket;
   /** message to display when packet is received
   */
	MessageString outputMessageForCurrentPacket;

	/** reference to external object */
	Network* dev;
	/** reference to external object */
	ReqAndStat* ras;

	Paths includePaths;
	Fields fields;
	/** any read word may be replaced by one of these strings */
	Substitutions globalDefines;
	/** stores what were added by KW_DEFINE command */
	Substitutions defines;
	SequenceOfPackets* buf;
	FieldVariableValues variables;

	/** regime of work, see SR_ defines */
	u_char reg;

   /** if not 0 then it's the number of a packet that will be a single one actually generated
   */
	int one_packet;

   /**
      when generating multiple packets (REP command)
      then interval between sending packets will be equal to this value
   */
	uint interval;

	int numberOfGenerations;

	/** number of main interface */
	int mainInterfaceNum;
   /** true - means that extended regime is active,
      in this regime requests for packets will have another syntax,
      see sendCommand, KW_DEFAULTS
   */
	bool extendedRegime;
	Convtest convtest;
   /**	used for correct processing of fasttest command when it appeares in not top level file,
      but in one from included
   */
	MessageString nameTopLevelFile;

	/** true: KW_FASTTEST command has been already processed */
	bool fastTestAlreadyProccessed;

	/** true - causes the object break any work */
	volatile bool needBreak;

	/** stores the search result performed by GOTO or GOTOB command */
	bool dataWasFound;

	/** true: currently executed cycle must be breaked */
	bool needBreakCycle;

   /**
      defined the number of repetitions while processing some kind of command or block of script
  */
   UInt numIterations;

	/** stores the result of last system call */
	int resultLastSystemCall;

public:

private:

	/**
	 determines is the given string compare qualifier (ex: >, <, ...) or not
	 return the type of compare or TCF_UNDEFINED if it's not compare qualifier
	*/
	TypeCompareField isCompareQualifier(const MessageString& word);

	/**
	 reads the sequence of requests from text (they are parameters to commands: send, wait and others)
	 the concrete command must be specified through its key word, the behavior may depend from command
	 usually calls method addPacketToRas
	*/
	void readRequests(int firstKeyWordID);

	/**
	 denotes the beginning of description of a new packet,
	 resets some temp parameters
	*/
	void newpac();

	/** calculates all auto calculated values for packet */
	void prepare_packet();

	/** increments 'autoIncrementedField' and sets its new value to current packet */
	void performAutoincrement();

	/** is called after meeting the name of field in text */
	void processFieldOcc(
		const FieldInfo& fieldParameters
		);

	void processFieldDefinition(
		const char* fieldName
		);

	/**
	 * @param keywordID key word that causes this sending
	 */
	void sendCommand(
		int keywordID
		);

	/** for KW_GDEF and KW_DEFINE commands */
	void processDefineCommand(
		bool global	// true: will be added to global substitutions, otherwise - to 'substitutionsOfValues'
		);

	/** processes KW_INCLUDE command */
	void processIncludeCommand(MessageString& nameIncludedFile);

	/** processes KW_VAR command */
	void processVarCommand(
		bool* bracketWasTyped	// see the parameters of the same name in run method
		);

	/** adds the current packet to 'ras' (see ReqAndStat :: addPacket) */
	void addPacketToRas(
		int num,
		Request req,
		int interfaceNum,
		int line_number
		);

	/** performs system call */
	void makeSystemCall(const MessageString& command);

	/** processes KW_ARM command */
	void processARepMakerCommand();

   void enableAutoincrement();
	void disableAutoincrement();

   CommandsProcessor* getProcessor(const MessageString& command);

   void runBlock(bool isIdleMode);

	void processDeprecatedCommands(int kw_id);
	void processElse(bool isProcess);

	class ReturnException : public Exception {
	public:
		ReturnException() : Exception() {}
	};

public:

   int getMainInterfaceNum();

   AutocalcManager* getAutocalcManager() const {
      return autocalcManager;
   }

   SequenceOfPackets* getBuf() const {
      return buf;
   }

   Convtest& getConvtest() {
      return convtest;
   }

   const Substitutions& getDefines() const {
      return defines;
   }

   Network* getDev() const {
      return dev;
   }

   Fields& getFields() {
      return fields;
   }

   const Substitutions& getGlobalDefines() const {
      return globalDefines;
   }

   const Paths& getIncludePaths() const {
      return includePaths;
   }

   ReqAndStat* getRas() const {
      return ras;
   }

   u_char getReg() const {
      return reg;
   }

   StresstestTextBuffer* getText() const {
      return text;
   }

   FieldVariableValues& getVariables() {
      return variables;
   }

   void setMainInterfaceNum(int num);

	/**
	 searches insertions like $name$ and resolves these names, i.e. inserts their values,
	 uses method searchEntity for resolving
	*/
	void putValuesInMessage(MessageString* message);

   /** reads next word from text at low-level,
    *  only global defines are applied
    */
	MessageString& read_word(MessageString& word, bool failOnEmptyWord = false, bool removeEnclosingCommas = false) throw(Exception*);

	/**
	 * reads the name of a entity (field, variable, etc.) when the name is needed, not its value
    */
	void readNameEntity(MessageString* word, bool failOnEmptyWord = true, TypeOfEntity typeOfEntity = SE_NOT_DEFINED) {

		readEntity(word,        true,          failOnEmptyWord, QP_NOT_PROCESS_QUOTES, true, false, true, typeOfEntity);
	}

	/**
	 * reads value resolving names of entities, quotes for string values are required, they will stay
    */
	int readValue(MessageString* word, bool failOnEmptyWord = true, bool failOnKeyword = true) {

		return readEntity(word, failOnKeyword, failOnEmptyWord, QP_NOT_PROCESS_QUOTES, false);
	}

	/**
	 * reads value resolving names of entities, quotes for string values are optional and will be removed
    */
	int readString(MessageString* word, bool failOnEmptyWord = true) {

		return readEntity(word, true,          failOnEmptyWord, QP_REMOVE_OPTIONAL_QUOTES,  false);
	}

	/**
	 * reads value resolving names of entities, quotes for string values are required and will be removed
    */
   int readStringRequireQuots(MessageString* word, bool failOnEmptyWord = true) {
		return readEntity(word, true,          failOnEmptyWord, QP_REMOVE_OPTIONAL_QUOTES, false, true);
	}

	/**
	 * reads string value (only this type) resolving names of entities, quotes for string values are required and will be removed
    */
	int readStringOnly(MessageString* word, bool failOnEmptyWord = true) {
		return readEntity(word, true,          failOnEmptyWord, QP_REMOVE_REQUIRED_QUOTES, false);
	}

   /**
    * General method to read next word and perform several common operations: resolve name of entity to its value,
    * put values instead of references in strings, etc
    * @param word [out] result of read
    * @param failOnKeyword true: throws Exception if it's a keyword
    * @param failOnEmptyWord true: if end of script throws Exception
    * @param removeEnclosingCommas see method searchEntity
    * @param doNotSearchEntity true: doesnt attempt to make the substitution of entity's name by its value (for fields, variables and others)
    * @param checkNotResolvedName see method searchEntity
    * @param resolveRef
    * @param typeOfEntity see searchEntity method
    * @return
    */
	int readEntity(MessageString* word,
      bool failOnKeyword,
      bool failOnEmptyWord,
      QuotesProccessing quotesProccessing,
      bool doNotSearchEntity,
      bool checkNotResolvedName = false,
      bool resolveRef = true,
      TypeOfEntity typeOfEntity = SE_NOT_DEFINED
      );

   /** searches the entity with given name amoung variable, fields, defines,
	 resolves it (replaces by value), for fields retrieves the value from current packet,
	 writes back the result to given name, if no entity found the name will not change
    also resolves some key values
    */
   void searchEntity(
		MessageString* name, // [in,out]
		QuotesProccessing quotesProccessing = QP_REMOVE_OPTIONAL_QUOTES,
		bool withTypeInfo = true,			// see method FieldValue :: getValueString which is used hear to retrieve the value of variable, etc
		bool doNotResolve = false,		// true: don't try to get value of entity, leave the name itself
		bool checkNotResolvedName = false, // true: if the name is not resolved then it must correspond to a type of value, otherwise Exception will raise
		TypeOfEntity typeOfEntity = SE_NOT_DEFINED	// type of entity which name is currently processed
		);

	Script(Network& device, ReqAndStat& externRas, TraceFile& traceFile, AutocalcManager& autocalcManager, u_char regime);
	~Script();

	void setCommandProcessors(vector<CommandsProcessor*> commandProcessors);

	void setRequestForBreak() { needBreak = true; convtest.needBreak = true; }

	/**
	 * Reads file and calls run method
	 */
	void processFile(const char* filename) throw(Exception*);

	/**
	 * processes previously loaded or given text
	 * step by step reads words from text (commands, field definitions and others)
	 */
	void run (
				const char* nameSource = 0, // text source's name (for error messages)
				const char* textToProcess = 0,  /* text to process
															 cannot be null while external call (outside the class),
															 if null then current 'text' will be processed
														 */
				bool isIdleMode = false, // true: only reads words, doesnt execute any command, until the end of block (KW_END_BLOCK)
            bool terminateByBlockEnd = false
				)
				throw(Exception*);



	/**
	 * adds path where included files are searched
	 */
	void add_include_path(const char* path) throw(Exception*);

	/**
	 * renders to initial state
	 * references to external objects may remain
	 * \param see SR_ defines
	 */
	void reset(
		UChar newRegime
		);

	/**
	 * sets device to work
	 * \param dev device
	 * \param mainInterfaceNum main interface of device from which to generate packets
	 */
	void set_device (
		Network* dev,
		int mainInterfaceNum
		);

	void printFieldsInfo() {
		fields.print();
	}

	bool isFasttestWasSpecified() { return fastTestAlreadyProccessed; }

	const char* getKeyWord(int kwID);

   void clearDefines() {
      defines.clear();
      globalDefines.clear();
   }

};

#endif //STRESSTEST_SCRIPT_H
