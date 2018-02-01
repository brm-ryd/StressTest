#ifndef VALUETYPES_H
#define	VALUETYPES_H

#include "stresstest.h"
#include "messagebuff.h"
#include "messagestring.h"
#include "fieldMask.h"
#include "typeinfo"
#include "logman.h"

#define ISDIG(x) (x>=0x30 && x<=0x39)

extern const TCHAR* MUST_BE_QUOTED_ERROR;
class AnettestTextBuffer;

/**
 * Holds and deletes given reference in destructor. Helps to avoid memory leaks.
 */
template <class T>
class RefHolder {

   T* _ref;

   void del() {
      if (_ref) {
         ADDTOLOG3("ReferenceHolder :: delete %p - %p", _ref, this);
         delete _ref;
         _ref = NULL;
      }
   }

public:

   RefHolder() : _ref(NULL) {
      ADDTOLOG2("ReferenceHolder :: init %p", this);
   }
   RefHolder(const RefHolder& o) { Test(); }
   T* ref() { return _ref; }
   /** deletes current reference and sets new */
   void set(T* newRef) { del(); _ref = newRef; };
   void operator=(const RefHolder& o) {Test();}
   void disable() { ref = NULL; }
   ~RefHolder() {
      del();
   }
};

const int numberOfValueTypes = 4; // !!! ATTENTION: must be changed after adding new types
enum TypeCode {

	VT_UNDEFINED_TYPE,
	/** hex number (with 0x or without it in some regime) */
	VT_HEX,
	/** decimal number */
	VT_DEC,
	/** sequence of characters */
	VT_STRING
};

/**
 * Size of a field.
 * May be undefined i.e. any size of value is permitted for the field.
 * May be undefined but with reserve that only while field initialization (firstly undefined):
 *    an arbitrary size of value given while field initialization becomes the size of field.
 */
class DefSize {

   UInt i;
   boolean undefined;
   boolean onlyFirstlyUndefined;
   boolean valueForVariable;

	void init() {
		undefined = false;
		onlyFirstlyUndefined = false;
		valueForVariable = false;
		i=0;
	}

public:

   static const DefSize UNDEFINED;
   static const DefSize UNDEFINED_FIRSTLY;
   static const DefSize FOR_VARIABLE;

   DefSize(UInt i) { init(); this->i=i; }
   DefSize() { init(); undefined=true; }
   DefSize(boolean onlyFirstlyUndefined) {
		init(); undefined=true; i=0; this->onlyFirstlyUndefined=onlyFirstlyUndefined;
	}
   DefSize(boolean onlyFirstlyUndefined, boolean valueForVariable) {
		init();
		undefined=true;
		i=0;
		this-> onlyFirstlyUndefined = onlyFirstlyUndefined;
		this-> valueForVariable = valueForVariable;
	}
   /**
    * Returns the size-number. Throws exception if size is undefined.
    * @return
    */
   const UInt& num() const { userCheck(!undefined); return i; }
   boolean isOnlyFirstlyUndefined() const {
      return onlyFirstlyUndefined;
   }
   boolean isUndefined() const { return undefined; }
   boolean isDefined() const { return !undefined; }
   boolean isForVariable() const { return valueForVariable; }
   /**
    * Returns true if given size of value is permitted
    * @param size
    * @return
    */
   boolean isPermitted(UInt size) const {
      return (undefined || size == i);
   }
   boolean operator==(const DefSize& s) const {
      return i==s.i && undefined==s.undefined && onlyFirstlyUndefined == s.onlyFirstlyUndefined;
   }

//   boolean operator!=(UInt n) const {
//      return (undefined || n != i);
//   }
};

class FieldValue;

/**
 * Type of value (number, general string, etc.). Base class for other special types of values.
 * Basically they define methods of transition between string representation of a value and corresponding raw sequence of bytes.
 */
class ValueType {

public:

   virtual const char* getName() const = 0;
   virtual const DefSize& getDefaultSize() const = 0;
   /**
    * Returns true if given string represents value of this type.
    * The string must have explicit indication of its type. Ex: '0x' before hexadecimal number, quoted string.
    * This method is called to determine the type of a value when there is no particular type required.
    */
   virtual boolean isAcceptedValue(const string& value) const = 0;
   /**
    * Parses 'string' that must represent a value of this type, writes raw value into buffer 'value'.
    * @param value [out]
    * @param string [in]
    * @param requiredSize required size of resulted value (size of field)
    * @return
    */
   virtual DBuffer getValueFromString(const string& string, DefSize requiredSize = DefSize :: UNDEFINED) const = 0;
   /**
    * Returns string representation of the raw 'value' of this type.
    * @param str [out]
    * @param value [in]
    * @param withTypeInfo
    * @return
    */
   virtual string toString(const DBuffer& value, boolean withTypeInfo = true) const = 0;

   virtual boolean operator==(const ValueType& other) const {
      // TODO: check this
      return (typeid(other) == typeid(*this));
   }
};

/**
 * Base types of values: dec, hex number, string.
 */
class BaseType : public ValueType
{
protected:
   TypeCode _code;
   BaseType(TypeCode code) { _code=code; }
   BaseType(const BaseType& t) { Test(); }

public:

   TypeCode code() const { return _code; }
   void operator=(TypeCode code) { _code = code; }
   const char* getName() const;
   const DefSize& getDefaultSize() const;

   boolean operator==(TypeCode c) const { return (_code == c); }
   boolean isAcceptedValue(const string& value) const;
   DBuffer getValueFromString(const string& str, DefSize requiredSize = DefSize :: UNDEFINED) const;
   string toString(const DBuffer& value, boolean withTypeInfo = true) const;

   static const BaseType DEC_TYPE;
   static const BaseType HEX_TYPE;
   static const BaseType STRING_TYPE;

   static bool isQuoted(const char* valueString);
   static string& getHexValueString(string& res, const DBuffer& buf, bool withTypeInfo);
   static bool isDecimalNumber(const char* valueString) {
		return is_dec(valueString);
	}
   static bool isHexNumber(const char* valueString);

   /**
   ! reads decimal number,
    returns 1 - incorrect or too big number
    0 - all right
   */
   static int read_dec_number(const char* number, decimal_number_type* tdec);
   /**
    determines does the given string represent hexadecimal number (some special symbols are allowed)
    '0x' prefix is required or optional depending on 'prefixRequired'
    if it's not a hexadecimal number then returns 0
    otherwise returns the number of digits (including the size of '0x' prefix if it exists)
   */
   static int is_hex(const char* , bool prefixRequired = false);
   /**! returns true if the string is correct decimal number with consideration of some other special symbols (is_legal_sym_for_number) */
   static bool is_dec(const char* );
};

class BaseTypeRevertedOrder : public BaseType {
	BaseTypeRevertedOrder(TypeCode code) : BaseType(code) {}
   BaseTypeRevertedOrder(const BaseTypeRevertedOrder& t) : BaseType(t) {}

	boolean isAcceptedValue(const string& value) const;
	DBuffer getValueFromString(const string& str, DefSize requiredSize = DefSize :: UNDEFINED) const;
	string toString(const DBuffer& value, boolean withTypeInfo = true) const;
public:
	static const string prefix;
	static const BaseTypeRevertedOrder HEX_REVERTED_TYPE;
	static const BaseTypeRevertedOrder HEX_REVERTED_TYPE_DEC;
};


class IPv4AddressType : public ValueType {

   static const DefSize defSize;

   IPv4AddressType() {}
   IPv4AddressType(const IPv4AddressType& aaddr) { Test(); }

   const char* getName() const { return "IP address"; }
   const DefSize& getDefaultSize() const { return defSize; }
   boolean isAcceptedValue(const string& value) const;
   DBuffer getValueFromString(const string& str, DefSize requiredSize = DefSize :: UNDEFINED) const;
   string toString(const DBuffer& value, boolean withTypeInfo = true) const;
public:
   static const IPv4AddressType TYPE;
   /** reads IPv4 address from string  */
   static void read_ip_address(
                     const char* string, // address in format n.n.n.n
                     u_int* address // [out] binary representation of address (network byte order)
                     );
};



class IPv6AddressType : public ValueType {

   static const DefSize defSize;

   IPv6AddressType() {}
   IPv6AddressType(const IPv6AddressType& s) {Test();}

   const char* getName() const { return "IPv6 address"; }
   const DefSize& getDefaultSize() const { return defSize; }
   boolean isAcceptedValue(const string& value) const;
   DBuffer getValueFromString(const string& str, DefSize requiredSize = DefSize :: UNDEFINED) const;
   string toString(const DBuffer& value, boolean withTypeInfo = true) const;

public:
   static const IPv6AddressType TYPE;
};



class MACAddressType : public ValueType {

   static const DefSize defSize;

   MACAddressType() {}
   MACAddressType(const MACAddressType& s) { Test(); }

   const char* getName() const { return "MAC address"; }
   const DefSize& getDefaultSize() const { return defSize; }
   boolean isAcceptedValue(const string& value) const;
   DBuffer getValueFromString(const string& str, DefSize requiredSize = DefSize :: UNDEFINED) const;
   string toString(const DBuffer& value, boolean withTypeInfo = true) const;

   static bool readMacAddr(const char* word, DBuffer* value);
public:
   static const MACAddressType TYPE;
};



/**
	Represents the value of a field combining raw data represented by DBuffer and associated type of value (ValueType).
*/
class FieldValue : public DBuffer {

   const ValueType* type;

public:

   FieldValue(const ValueType* _type) : type(_type) {
   }

	/**
	 shifts all bits in given buffer to the left (offset > 0) or to the right (offset < 0)
	 the space is filled by zeros
	*/
	static void offsetBuffer(
		u_char* buf,
		int sizeBuf,
		int offset	// size of shift (in bits)
		);

	/** copies 'valueToWrite' to 'modifiedBuf' with given mask */
	static void copyWithMask(u_char* modifiedBuf, UInt sizeBuf, const u_char* valueToWrite, UInt sizeValue, const FieldMask& mask);

	/** gets string representing currently stored value */
	MessageString getValueString(
		bool withTypeInfo = true /* true: e.g. strings will be enclosed in quotation marks, hexadecimal number will have 0x prefix,
											 it permits of not losing the type of value in several operations
										 */
		) const;

	/** sets new value represented by string */
	virtual void readValue(
		const char* valueString, // new value
		DefSize sizeField = DefSize :: UNDEFINED // is used while reading decimal numbers
		);

	const ValueType& getType() const { return *type; }

	bool operator==(const FieldValue& otheValue) {
		return *type == otheValue.getType() && this -> isTheSameContent(otheValue);
	}

	/**
	 performs addition or subtraction of currently stored value,
	 adds the given number to object's value that is interpreted as a sequence of bytes,
	 the carrying is applied through all the value from the least significant right byte to the left one
	*/
	void changeValue(
		int additionValue // may be negative
		);
};

#endif	/* S_H */
