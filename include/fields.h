#ifndef FIELDS_H
#define FIELDS_H

#include "stresstest.h"
#include "exceptions.h"
#include "messagebuff.h"
#include "fieldMask.h"
#include "mutex.h"
#include "valuetypes.h"

#define DATA_FIELD "data"

/**
   Field of network packet.

    Properties:
      Name;
      Position - number of first byte of field (counting from the beginning of packet's buffer);
      Size - number of bytes, size of field;
      Type - type of value (class ValueType);
      Mask - field's mask (class FieldMask);
      Offset - number of bits from byte border (0-7), each value for field will be offset while writing.
         Offset = n means that while writing K the actual written value will be K*2^n;

 *
 */
class FieldInfo {

	/** th name of field */
	MString name;
	/** position (offset from the beginning of packet on channel level) */
	UInt pos;
	/** type of value */
	const ValueType* type;
	/** size of field, may be UNDEFINED_FIELD_SIZE */
	DefSize size;

	int offset;

	/** mask of field */
	FieldMask* mask;

	MString* description;

   void init(const FieldInfo& f);
	void deletePointers();

public:

   FieldInfo(const FieldInfo& f);

   void operator=(const FieldInfo& f);

   FieldInfo(const MString& name, UInt pos, const ValueType& type, int offset, const FieldMask* mask, const MString* description, UInt size);
   ~FieldInfo();
   boolean operator==(const FieldInfo& f) const;

   const MString* getDescription() const {
      return description;
   }

   const FieldMask& getMask() const {
      static const FieldMask fullMask;
      if (!mask) return fullMask;
      return *mask;
   }

   const MString& getName() const {
      return name;
   }


   int getOffset() const {
      return offset;
   }

   UInt getPos() const {
      return pos;
   }

   DefSize getSize() const {
      return size;
   }

   const ValueType& getType() const {
      return *type;
   }

   void setPos(int pos) {
      this->pos=pos;
   }

   void setSize(DefSize size) {
      if (getType().getDefaultSize().isDefined())
         throw new Exception("the size of field % cannot be changed", !name);
      this->size = size;
   }

   const DefSize& getDefaultSizeOfField() const { return type->getDefaultSize(); }
   const char* getNameOfType() const { return type->getName(); }
};


/**
	Manages set of registered fields (FieldInfo class).
 * Stores default mask and offset which are used while addition of new fields.
*/

class Fields {

	/** array */
	vector<FieldInfo> field;
	/** current mask, used while adding new fields */
	FieldMask* def_mask;
	/** current offset, used while adding new fields */
	int def_offset;
							// see fields of struct Field

	MyMutex sharedAccessMutex;

	/**FORBID_COPING(Fields); */

	void addBaseFields();

	void deleteField(const MString& name);

 public:

	Fields();
	~Fields();

	/** removes the field with given number from array */
	void deleteRecord(UInt numberRecordToDelete) {
		check(numberRecordToDelete < field.size());
      field.erase(field.begin() + numberRecordToDelete);
	}

	/**
	 adds new field,
	 default mask will be set to the fully filled mask,
	 default offset will be set to 0,
	 if any field with given name is already exist then it will be overriden
	*/
	void addfield(const char* name, // name of field
					 UInt pos,	 // position of field
					 const ValueType& type, // type of field
                UInt size = 0,
                const MString* description = Null
					 );

   /** like getField but throws Exception if not found*/
   const FieldInfo* getFieldEx(const MString& name, UInt* numFoundRecord = Null) const;

	/**
	  search the field with given name.
     returns null if not found
	*/
	const FieldInfo* getField(const MString& name, // name of sought field
							//Field* fieldParameters, // [out] parameters of found will be written in it
															// may be 0
							UInt* numFoundRecord = Null // [out] index of found field in internal array
							) const;

	/**
	 returns default mask (see def_mask)
	 must be used temporarily and only for reading
	*/
	const FieldMask* getmask();

	/** sets default mask (see def_mask) */
	void setmask(const char* value // hex number

			) throw (Exception*);

	/** sets default offset */
	void set_def_offset(int new_def_offset) throw (Exception*);

	/** returns def_offset */
	int get_def_offset();

	/** removes all added fields */
	void clear();

	/** prints info about fields as table */
	void print(
		const char* soughtName = Null // if not Null then will be displayed only fields which name contains 'soughtName'
		);

	/** sets new size of field */
	void setSizeOfField(const MString& nameOfField, DefSize newSize);

	/** sets new position of field */
	void setPositionOfField(const MString& nameOfField, UInt newPosition);
};

#define ICR_OK					1		// value from packet is the same
#define ICR_OTHER_VALUE		0		// value from packet is not the same
#define ICR_NOT_SUCH_FIELD	(-1)	// the packet is too small to contain this field



/**
	Class CommonField - the field of network header (FieldInfo object) with associated value.
   Provides methods for writing value in packet's buffer, reading, checking equality.
 *
*/
class CommonField
{

public:

private:

	/** stored value of field */
	FieldValue* value;
   FieldInfo params;

private:

	// methods for work with complex fields (not null offset or not trivial mask)

	/** writes field's value to packet's buffer */
	void fillComplexField(u_char* buf, UInt sizeBuf) const;

	/** copies field's value from packet's buffer */
	void setComplexFieldByPacket(const u_char* buf, UInt sizeBuf);

	/** returns true if field's value is equal to what is in the given packet's buffer */
	bool isComplexFieldContent(const u_char* buf, UInt sizeBuf) const;

public:

	CommonField(const CommonField& sourceCommonField);

	CommonField(
		const Fields& fields,
		const MString& field_name
		);

	CommonField(const FieldInfo& fieldParameters);

	~CommonField();

   const FieldInfo& getFieldInfo() const {
      return params;
   }

	/**
	 compares field's value with what in packet' buffer,
	 returns ICR_ values
	*/
	int isContent(const u_char* buf, UInt sizeBuf) const;

	/**
	 write field's value to packet's buffer,
	 returns 'ICR_OK' or 'ICR_NOT_SUCH_FIELD'
	*/
	int fillPacket(u_char* buf, int sizeBuf) const;

	/** sets field's value by what is in packet's buffer.
    * returns 'ICR_OK' or 'ICR_NOT_SUCH_FIELD'
    */
	int setByPacket(const u_char* buf, int sizeBuf);

	void operator=(const CommonField& sourceCommonField);

	bool isTheSameValue(const CommonField& otherCommonField) const {

		return (*value == *(otherCommonField.value));
	}

	/**
	 checks the equality of parameters and the stored values of fields,
	 returns true if equal
	*/
	bool operator==(const CommonField& otherCommonField) const {

		if (!isTheSameType(otherCommonField)) return false;
		if (!isTheSameValue(otherCommonField)) return false;

		return true;
	}

	/**
	 checks the equality of parameters of two fields,
	 values are not considered,
	 returns true if equal
	*/
	bool isTheSameType(const CommonField& f) const {
      return (params == f.params);
	}

   /**
    * Sets value
    * @param value must have size equal to the size of field if the latter has been defined
    */
	void setValue(const DBuffer& value) {

		if (!params.getSize().isPermitted(value.getSize())) {
			throw new Exception("size of value %u not correspond to size of field %u", value.getSize(), params.getSize().num());
		}
		*((DBuffer*)(this -> value)) = value;
	}

	virtual void readValue(
		const char* value
		) throw(Exception*);

	const FieldValue& getValue() const {
		return *value;
	}

	/**
	 returns the size of field,
	*/
	DefSize getSizeField() const { return params.getSize(); }

	/**
	 returns the size of currently stored value,
	 may return size = 0
	*/
	uint getSizeValue() const { return value -> getSize(); }

	/** return position of field >= 0 */
	uint getPositionInPacket() const { return params.getPos(); }

	bool isSimpleField() const {

		if (params.getMask().isWholeField() && params.getOffset() == 0) return true; else return false;
	}

	/** calls FieldValue :: getValueString */
	MString getValueString(
		bool withTypeInfo = true	// see FieldValue :: getValueString
		) const;

	/** adds the given value to field's value */
	void changeValue(int additionValue) {

		value -> changeValue(additionValue);
	}
};





#endif // FIELDS_H
