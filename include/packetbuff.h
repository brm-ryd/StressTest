//#ifndef PACKETBUFF_H
//#define PACKETBUFF_H

#include "stresstest.h"
#include "stresstest_functs.h"
#include "mbuffer.h"
#include "fields.h"
#include "protocolsExpert.h"
#include "network.h"
//#include "tracefile.h"
//#include "convimit.h"

class TraceFile;
class SequenceOfPackets;
class Packet;

enum TypeCompare {
	BC_BYMASK
};

enum TypeCompareField {

	TCF_EQUAL,
	TCF_NOT_EQUAL,
	TCF_GREATER,
	TCF_LESS,
	TCF_GREATER_EQUAL,
	TCF_LESS_EQUAL,

	/** control values */
	TCF_NUM_TYPES,
	TCF_UNDEFINED
};

/** Single condition in packet mask.
 Combines object of CommonField class and TypeCompareField
 */
class MaskCondition {

	TypeCompareField typeCompareField;
	/* packet field with stored value */
	CommonField field;

public:

	MaskCondition(const CommonField& sfield, TypeCompareField typeCompareField) : field(sfield)
	{
		this -> typeCompareField = typeCompareField;
	}

   TypeCompareField getTypeCompareField() const {
      return typeCompareField;
   }

   const CommonField& getField() const {
      return field;
   }

	/**
	 checks condition two operands,
	 some types of conditions the operands must numbers
	*/
	static bool isConditionMet(

		const MString& firstItem,
		const MString& secondItem,
		TypeCompareField typeCompare
		);
};

/**
	Class Packet
*/

#define ERROR_FOR_FIXED_MASK  { if (maskFixed) throw new Exception("operation is not permitted while mask is fixed, unfix it"); }

class Packet
{
	bool maskFixed;

	/* not null byte in array indicates that this byte is included in simple mask */
	DBuffer simpleMask;
	/* array of bytes */
	DBuffer contentOfPacket;
   /* these conditions are additionally used to extend the facilities of simpleMask,
      when some added field is not simple (mask and offset are not trivial),
      or the type of comparing is not simple (TypeCompareField)
   */
	vector<MaskCondition> extraConditions;

	void excludeRegionFromMask(UInt startPosition, UInt sizeOfRegion);

public:

	Packet() {

		DB("packet");

		maskFixed = false;

		simpleMask.fillByZero = true;
		contentOfPacket.fillByZero = true;
	}

	~Packet() {
	}

	/** adds the new field in mask, also fills the content of packet by the value of given field */
	void addField(const CommonField& newField, TypeCompareField typeCompareField);

	/** simply fills the content of packet by given value, the simple mask of packet will be also changed */
	void simpleFill(const u_char* value, UInt sizeValue, UInt positionInPacket);

	/**
	 exclude from mask every field having the same type as given one,
	 exclude from mask the region corresponding the given field
	*/
	void excludeFromMask(const CommonField& excludedField);

	/** true - corresponds, otherwise - false */
	bool isPacketCorrespondsTheMask(u_char* buf, uint sizeBuf) const;

	uint getSizeOfPacket() const { return contentOfPacket.getSize(); }

	void fillMask(UInt sizeOfFilled);

	/* reset  mask, the content of packet will remain the same */
	void clearMask() {

		ERROR_FOR_FIXED_MASK

      extraConditions.clear();
		simpleMask.setSize(0);
	}

	const DBuffer& getContentOfPacket() const { return contentOfPacket; }

	void setMinimalSize(UInt minimalSize) {

		if (minimalSize > contentOfPacket.getSize())
			contentOfPacket.setSize(minimalSize);
	}

	void send(Network* device, int interfaceNum, UInt startPosInContentOfPacket, UInt sizeOfBlockToSend) {

		setMinimalSize(device -> getInterface(interfaceNum) -> getMinimalSizeOfPacket() + startPosInContentOfPacket);

		check(startPosInContentOfPacket + sizeOfBlockToSend <= contentOfPacket.getSize());

		device -> getInterface(interfaceNum) -> send(!contentOfPacket + startPosInContentOfPacket,
			sizeOfBlockToSend > device -> getInterface(interfaceNum) -> getMinimalSizeOfPacket() ? sizeOfBlockToSend : device -> getInterface(interfaceNum) -> getMinimalSizeOfPacket()
			);
	}

	/** calls AutocalcManager :: computeAndSetValues for this packet */
   void calcAllAutoCalcValues(AutocalcManager* autocalcManager, UInt sizePacketBuff);

   /** returns the number of matched packets
    */
   UInt searchForMatch(TraceFile& trace, TypeCompare typeCompare) const;

	/** copies the content of packet to the given buffer */
	void cpyBuf(void* dest_address, UInt size) const {

		check(dest_address);

		contentOfPacket.get(
			dest_address,
			size < contentOfPacket.getSize() ? size : contentOfPacket.getSize(),
			0);
	}

   /** cuts down the packet reducing released memory*/
	void reduceSize(UInt newSize) {

		if (newSize < contentOfPacket.getSize()) contentOfPacket.setSize(newSize);
		if (newSize < simpleMask.getSize()) simpleMask.setSize(newSize);
	}

	/** fixes mask to avoid its modifications whereas packet's content may still be changed */
	void fixMask() { if (maskFixed) throw new Exception("mask is already fixed"); maskFixed = true; }
	void unfixMask() { if (!maskFixed) throw new Exception("mask is not fixed"); maskFixed = false; }
};


enum FillMode {
	LIMITED_SIZE,
	UNLIMITED_SIZE,
	UNLIMITED_SIZE_DEFENITION
};

/*
	Class is used to manage the process of packet's modification while processing a script.
	Use Packet object internally and provides methods to successively modify it.
*/

class SequenceOfPackets {

	Packet currentPacket;

	UInt maxPacketSize;

    /** initial position of sent data, before this position data is not considered (see function send) */
    UInt init_pos;

	/** beyond this size content has not been modified */
	UInt inheritedSize;

	/** maximum position of a field whose value has been specified while processing current packet description */
	UInt max_field_pos;
	/** max_field_pos for previous defined packet */
	UInt last_max_field_pos;

	/** maximum value of 'pos' that has been*/
	UInt max_pos;
	/** current position of byte pointer */
	UInt pos;

public:

	AutocalcManager& autocalcManager;

private:

	void processFilling(UInt sizeOfFilledBlock, bool isStartNewField, FillMode fillMode);

public:

	SequenceOfPackets(UInt maxPacketSize, // buffer's size
				UInt init_pos, // initial position before which data is not altered or send
           AutocalcManager& autocalcManager
				);
	~SequenceOfPackets();

	/** sets mask of packet so mask corresponds to whole packet (based on currentSize of packet) */
	void setFullMask();

	/** sets value of field (modifies packet's content), also adds new equality condition to mask  */
	void setFieldValue(const CommonField& field, bool definition);

	/** adds the special condition to mask (for not simple fields or for special conditions, see Packet) */
	void addSpecialCondition(const CommonField& field, TypeCompareField typeCompareField);

	/** starts descriptions of new packet */
	void startNewPacket();

	/** clears history of packets description */
	void clear_history();

	/** resets mask */
	void clearMask();

	/** starts new sequence of packets */
	void reset();

   void updateUponInterfaceChange(Interface* i);

	/** determines and returns the size of packet (history of packets description is considered) */
	int getCurrentSize();

	/** sends packet from main interface of device of given script */
	void send(Script* script);

	/** returns initial position */
	int getinitpos();

	/**
    sets current position of byte pointer,
    throw new Exception
   */
   void setpos(UInt new_pos);

	/** copies current packet'content to the given buffer */
	void cpyBuf(
		void* dest_address,
		UInt size
	);

	/** sets raw value for packet, modifies the packet's buffer and mask */
	void simpleFill(
		const u_char* valueToWrite,
		UInt sizeValue,
		bool isStartNewField,	// true - this value is a new field (starts of new field)
		FillMode fillMode
	);

	/** excludes specified field from mask of packet */
	void excludeFromMask(const CommonField& excludedField) {

		currentPacket.excludeFromMask(excludedField);
	}

	UInt getPos() { return pos; }

	const Packet& getPacket() { return currentPacket; }

	/**
	 returns packet with size reduced to correspond the current size of packets sequence,
	 ATTENTION: returned pointer is valid until to the next call to this method
	*/
	const Packet* getPacketSpecial() {

		static Packet returnedPacket;

		returnedPacket = currentPacket;
		returnedPacket.reduceSize(getCurrentSize());
		return &returnedPacket;
	}

	/** sets values for all fields for which special auto-values have been specified */
	void calcAllAutoCalcValues() {

		currentPacket.calcAllAutoCalcValues(&autocalcManager, getCurrentSize());
	}

	/** rewrites content of packet by given packet */
	void setFullPacket(const UChar* buf, UInt sizePacketBuff) {

		clear_history();
		clearMask();

		// TODO
		setpos(init_pos);

		simpleFill(buf + init_pos, sizePacketBuff - init_pos, true, UNLIMITED_SIZE);
		startNewPacket();
	}

	void fixMask() { currentPacket.fixMask(); }

	void unfixMask() { currentPacket.unfixMask(); }
};

#endif //PacketBuff_H
