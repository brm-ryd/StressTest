#include "valuetypes.h"
#include "stresstestTextBuffer.h"

//#include <pcap-stdinc.h>

const BaseType BaseType ::  DEC_TYPE(VT_DEC);
const BaseType BaseType ::  HEX_TYPE(VT_HEX);
const BaseType BaseType ::  STRING_TYPE(VT_STRING);

const BaseTypeRevertedOrder BaseTypeRevertedOrder ::  HEX_REVERTED_TYPE(VT_HEX);
const BaseTypeRevertedOrder BaseTypeRevertedOrder ::  HEX_REVERTED_TYPE_DEC(VT_DEC);

const string BaseTypeRevertedOrder ::  prefix("r-");

const IPv6AddressType IPv6AddressType :: TYPE;
const IPv4AddressType IPv4AddressType :: TYPE;
const MACAddressType MACAddressType :: TYPE;

const DefSize IPv4AddressType :: defSize((UInt)4);
const DefSize IPv6AddressType :: defSize((UInt)16);
const DefSize MACAddressType :: defSize((UInt)6);
const DefSize DefSize :: UNDEFINED;
const DefSize DefSize :: UNDEFINED_FIRSTLY((boolean)true);
const DefSize DefSize :: FOR_VARIABLE(false, true);

const TCHAR* MUST_BE_QUOTED_ERROR = "if it's not the name of a entity then a string must be quoted";

boolean BaseTypeRevertedOrder :: isAcceptedValue(const string& value) const {
	if (value.find(prefix) == 0) {
		string val = value.substr(prefix.size(), string :: npos);
		return BaseType :: isAcceptedValue(val);
	}
	return false;
}

DBuffer BaseTypeRevertedOrder :: getValueFromString(const string& str, DefSize requiredSize /* = UNDEFINED_FIELD_SIZE */) const {
	string val;
	if (str.find(prefix) == 0) {
		val = str.substr(prefix.size(), string :: npos);
	}
	else {
		val = str;
	}
	DBuffer value;
	value = BaseType :: getValueFromString(val, requiredSize);
	rev_order(value.getPointer(), value.getSize());
	value.unblock();
	return value;
}

string BaseTypeRevertedOrder :: toString(const DBuffer& value, boolean withTypeInfo) const {
	DBuffer v = value;
	rev_order(v.getPointer(), v.getSize());
	v.unblock();
	return BaseType :: toString(v, withTypeInfo);
}

boolean BaseType :: isAcceptedValue(const string& value) const {

   userCheck(numberOfValueTypes == 4); // you must add new block to function, then change this number

   switch (_code) {
      case VT_DEC: return BaseType :: isDecimalNumber(value.c_str());
      case VT_HEX: return BaseType :: isHexNumber(value.c_str());
      case VT_STRING: return BaseType :: isQuoted(value.c_str());
   }

   return false;
}

DBuffer BaseType :: getValueFromString(const string& str, DefSize requiredSize /* = UNDEFINED_FIELD_SIZE */) const {

   userCheck(numberOfValueTypes == 4); // you must add new block to function, then change this number
   switch (_code) {

      case VT_DEC:
         return StresstestTextBuffer :: readNumber(str.c_str(), requiredSize);

      case VT_HEX:
         return StresstestTextBuffer :: readNumber(str.c_str(), requiredSize);

      case VT_STRING:

         try
         {
            MessageString s(str.c_str());
            if (!StresstestTextBuffer :: isQuoted(s))
               throw new Exception(MUST_BE_QUOTED_ERROR);
            StresstestTextBuffer :: removeEnclosingCommas(&s);
				DBuffer value;
            value.fill((const void*)!s, s.size(), 0);
            return value;
         }
         ADD_TO_ERROR_DESCRIPTION("reading value of type STRING");
         break;
   }

   Test();

// read MAC
//	if (!value && MACAddressFieldValue :: isMacAddress(word)) {
//
//		value =  new MACAddressFieldValue();
//      value -> readValue(word);
//	}
//
//  read IP address
//	if (!value && IPv4AddressFieldValue :: isIPAddress(word)) {
//
//		value = new IPv4AddressFieldValue();
//	}
//
//	if (!value && IPv6AddressFieldValue :: isIPv6Address(word)) {
//
//		value = new IPv6AddressFieldValue();
//	}
//
//	if (StresstestTextBuffer :: defaultFormatNumber == ND_DEC) {
//
//		// as decimal at first, then as hexadecimal
//
//		if (!value && DecimalFieldValue:: isDecimalNumber(word)) {
//
//			value = new DecimalFieldValue();
//		}
//
//		if (value==NULL && FieldValue :: isHexNumber(word)) {
//
//			value = new FieldValue();
//		}
//	}
//	else {
//
//		// as hexadecimal at first, then as decimal
//
//		if (!value && FieldValue :: isHexNumber(word)) {
//
//			value = new FieldValue();
//		}
//
//		if (!value && DecimalFieldValue :: isDecimalNumber(word)) {
//
//			value = new DecimalFieldValue();
//		}
//	}
//
//   // reading a string
//
//	if (!value && (StringFieldValue :: isQuoted(word) || implicitString)) {
//
//		value = new StringFieldValue();
//	}
}

string BaseType :: toString(const DBuffer& value, boolean withTypeInfo /* = true */) const {

	string string;
   userCheck(numberOfValueTypes == 4); // you must add new block to function, then change this number

   ostringstream ss;

   switch (_code) {
      case VT_DEC:

         if (value.getSize() <= sizeof (decimal_number_type))
         {
            decimal_number_type num = 0;

				value.get(&num, value.getSize());
				rev_order(&num, value.getSize());

				ss << dec << num;
				string = ss.str();
				return string;
         }

      case VT_HEX:

         getHexValueString(string, value, withTypeInfo);
         return string;

      case VT_STRING:

         if (withTypeInfo) ss << '"';
         for (int i = 0; i < value.getSize(); i++) {

            ss << hex << (char)value.getChar(i);
         }
         if (withTypeInfo) ss << '"';
         string = ss.str();
         return string;

      default: Test();
   }
}

bool BaseType :: is_dec(const char* number) {

	int i;

	for (i = 0; number[i]; i++) {

		if (number[i] < '0' || number[i] > '9') {

			if (
					(
						is_legal_sym_for_number(number[i])
						&& number[i] != 'u'
						|| (number[i] == '.' && number[i+1] == 0)
					)

					&& i != 0
				)
				continue;

			else return false;
		}
	}
	return true;
}

const DefSize& BaseType:: getDefaultSize() const {

   userCheck(numberOfValueTypes == 4); // you must add new item to switch block, then change this number

   switch (_code) {

      case VT_UNDEFINED_TYPE: return DefSize :: UNDEFINED;
      case VT_HEX:
      case VT_DEC: return DefSize :: UNDEFINED_FIRSTLY;
      //case VT_IPADDR: return 4;
      case VT_STRING: return DefSize :: UNDEFINED;
      //case VT_MACADDR: return 6;
      //case VT_IPV6ADDR: return 16;
      default: Test();
   }
}

const char* BaseType :: getName() const {

   userCheck(numberOfValueTypes == 4); // you must add new item to switch block, then change this number

   switch (_code) {

      case VT_UNDEFINED_TYPE: return "undefined type";
      case VT_HEX: return "HEX";
      case VT_DEC: return "INT";  // TODO[at] default size is 1 byte, must be increased
      //case VT_IPADDR: return "IP address";
      case VT_STRING: return "STRING";
      //case VT_MACADDR: return "MAC address";
      //case VT_IPV6ADDR: return "IPv6 address";
      default: Test();
   }
}

bool BaseType :: isHexNumber(const char* valueString) {

   if (
      ISDIG(valueString[0])
      || (
            valueString[0]
            && (u_int)is_hex(valueString, true) == strlen(valueString)
         )
      )
          {
             return true;
          }

   return false;
}

bool BaseType :: isQuoted(const char* valueString) {
   if (valueString[0] == '\'' || valueString[0] == '"') {
      return true;
   }
   return false;
}

string& BaseType :: getHexValueString(string& res, const DBuffer& buf, bool withTypeInfo) {

   ostringstream ss;

	if (withTypeInfo) {

		/*
		if (getSize() >= 8) {

			throw new Exception("using hexadecimal value with size > 8, it's not available in current context");
		}
		*/
		ss << "0x";
	}

   bool insertColomn = buf.getSize() > 4;

	for (int i = 0; i < buf.getSize(); i++) {

		// divides bytes by , divides every 8 bytes
		if (!withTypeInfo && i) {

			//if (getSize() >= 8) {

				if (i % 16 == 0) ss << endl;
				else {

					if (i % 8 == 0) ss << " :: ";
					else if (insertColomn) ss << ':';
				}
			//}
		}

		ss.fill('0');
		ss.width(2);
		ss << hex << (UInt)buf.getChar(i);
	}

   res.assign(ss.str());
   return res;
}

int BaseType :: read_dec_number(const char* number, decimal_number_type* tdec) {

   return !(sscanf(number, DECIMAL_NUMBER_FORMAT, tdec) == 1);
//	int i;
//	u_int mult,dec,ldec;
//
//	for (i=0; number[i] >= '0' && number[i] <= '9'; i++);
//	if (i==0) return 1;
//	i--;
//   mult = 1;
//   dec=0;
//   for (; i>=0; i--) {
//
//      if (mult == 1000000000) if (number[i]>'4') return 1;
//      ldec = dec;
//      dec += mult * (number[i]-'0');
//		if (dec<ldec) return 1;
//		if (mult == 1000000000) break;
//		mult *= 10;
//	}
//	*tdec=dec;
//	return 0;
}

int BaseType :: is_hex(const char* word, bool prefixRequired) {

   int ind;
   int i;

   ind = 0;
   i = 0;
   if (word[0]=='0' && word[1]=='x') {
      i = 2;
   }
   else {
      if (prefixRequired) return 0;
   }

   for (; word[i]; i++) {

      if (
				!(word[i]>=0x30 && word[i]<=0x39)
				&& !(word[i]>=0x61 && word[i]<=0x66)
			) {

         if (

					(is_legal_sym_for_number(word[i])
					//|| (word[i]=='.' && word[i+1]==0)
					)
					&& i
					&& (i != 2 || word[1] != 'x')
				) {

            if (!ind) ind = i;
				continue;
         }

         i=0;
         ind=0;
			break;
      }
   }
   if (!ind) ind = i;
   return ind;
}

DBuffer IPv4AddressType :: getValueFromString(const string& str, DefSize requiredSize) const{

   try
   {
		DBuffer value;
      u_int addr;
      read_ip_address(str.c_str(), (u_int*)&addr);
      value.setSize(0);
      value.fill(&addr, 4);
      return value;
   }
   ADD_TO_ERROR_DESCRIPTION("reading value with type IP ADDRESS");
}

boolean IPv4AddressType :: isAcceptedValue(const string& value) const {
   UInt ar[4];

   if (sscanf(value.c_str(),"%u.%u.%u.%u",&ar[0],&ar[1],&ar[2],&ar[3]) == 4) {
      return true;
   }

   return false;
}

string IPv4AddressType :: toString(const DBuffer& value, boolean withTypeInfo /* = true */) const{
   ostringstream ss;
   ss << (UInt)value.getChar(0) << '.' << (UInt)value.getChar(1) << '.' << (UInt)value.getChar(2) << '.' << (UInt)value.getChar(3);
   return ss.str();
}

DBuffer IPv6AddressType :: getValueFromString(const string& str, DefSize requiredSize) const{
   try {

		UInt ar[8];

		//read_ip_address(valueString, (u_int*)&addr);
		if (sscanf(str.c_str(), "%4x:%4x:%4x:%4x:%4x:%4x:%4x:%4x", &ar[0], &ar[1], &ar[2], &ar[3], &ar[4], &ar[5], &ar[6], &ar[7])
			!= 8)
			throw new Exception("'%s' - incorrect address", str.c_str());

		DBuffer value;
		for (UInt i = 0; i < 8; i++) {

			rev_order(&ar[i], 2);
         value.setSize(0);
			value.fill(&ar[i], 2, i*2);
		}
		return value;
	}

	ADD_TO_ERROR_DESCRIPTION("reading value with type IPv6 ADDRESS");
}

boolean IPv6AddressType :: isAcceptedValue(const string& value) const {
   UInt ar[8];

   if (sscanf(value.c_str(),"%4x:%4x:%4x:%4x:%4x:%4x:%4x:%4x",&ar[0],&ar[1],&ar[2],&ar[3],&ar[4],&ar[5],&ar[6],&ar[7]) == 8) {

      return true;
   }

   return false;
}

string IPv6AddressType :: toString(const DBuffer& value, boolean withTypeInfo /* = true */) const{
   ostringstream ss;

   ss.fill('0');
	ss.width(2);
	ss << hex << (UInt)value.getChar(0);
	ss.width(2);
	ss << hex << (UInt)value.getChar(1);
	ss << ':';
	ss.width(2);
	ss << hex << (UInt)value.getChar(2);
	ss.width(2);
	ss << hex << (UInt)value.getChar(3);
	ss << ':';
	ss.width(2);
	ss << hex << (UInt)value.getChar(4);
	ss.width(2);
	ss << hex << (UInt)value.getChar(5);
	ss << ':';
	ss.width(2);
	ss << hex << (UInt)value.getChar(6);
	ss.width(2);
	ss << hex << (UInt)value.getChar(7);
	ss << ':';
	ss.width(2);
	ss << hex << (UInt)value.getChar(8);
	ss.width(2);
	ss << hex << (UInt)value.getChar(9);
	ss << ':';
	ss.width(2);
	ss << hex << (UInt)value.getChar(10);
	ss.width(2);
	ss << hex << (UInt)value.getChar(11);
	ss << ':';
	ss.width(2);
	ss << hex << (UInt)value.getChar(12);
	ss.width(2);
	ss << hex << (UInt)value.getChar(13);
	ss << ':';
	ss.width(2);
	ss << hex << (UInt)value.getChar(14);
	ss.width(2);
	ss << hex << (UInt)value.getChar(15);

   return ss.str();
}

DBuffer MACAddressType :: getValueFromString(const string& str, DefSize requiredSize) const{
	DBuffer value;
   if (!readMacAddr(str.c_str(), &value))
		throw new Exception("incorrect MAC address for '%s'", str.c_str());
	return value;
}

boolean MACAddressType :: isAcceptedValue(const string& value) const {
   DBuffer res;
   return readMacAddr(value.c_str(), &res);
}

bool MACAddressType :: readMacAddr(const char* word, DBuffer* value) {

	unsigned int ar[6];

	value -> setSize(0);

	if (sscanf(word,"%x:%x:%x:%x:%x:%x",&ar[0],&ar[1],&ar[2],&ar[3],&ar[4],&ar[5]) == 6
		|| sscanf(word,"%x-%x-%x-%x-%x-%x",&ar[0],&ar[1],&ar[2],&ar[3],&ar[4],&ar[5]) == 6) {

		bool correct = true;

		for (int i = 0; i < 6; i++)
			if (ar[i] > 255) correct = false;

		if (correct) {

			for (int i = 0; i < 6; i++) {

				value -> setByte(i, (UChar)ar[i]);
			}

			return true;
		}
	}

	// read as hex number

	if (BaseType :: is_hex(word) == 12 || BaseType :: is_hex(word) == 14) {

		bool correct = true;

		try
		{
			readHexNumber(word, (UInt)6, *value);
		}
		catch (Exception*) {

			correct = false;
		}

		if (correct) return true;
	}

	return false;
}

string MACAddressType :: toString(const DBuffer& value, boolean withTypeInfo /* = true */) const{

   ostringstream ss;

   ss.fill('0');
	ss.width(2);
	ss << hex << (UInt)value.getChar(0) << ':';
	ss.width(2);
	ss << hex << (UInt)value.getChar(1) << ':';
	ss.width(2);
	ss << hex << (UInt)value.getChar(2) << ':';
	ss.width(2);
	ss << hex << (UInt)value.getChar(3) << ':';
	ss.width(2);
	ss << hex << (UInt)value.getChar(4) << ':';
	ss.width(2);
	ss << hex << (UInt)value.getChar(5);

   return ss.str();
}

void FieldValue :: offsetBuffer(u_char* buf, int sizeBuf, int offset) {

	u_int dword;
	u_char offsetedByte;

	if (offset == 0) return;

	check(offset > -8 && offset < 8);

	u_char* origBuf = new u_char[sizeBuf];
	for (int i = 0; i < sizeBuf; i++) origBuf[i] = buf[i];

	offsetedByte = 0;

	if (offset > 0)

		for (int i = sizeBuf - 1; i >= 0; i --) {

			buf[i] = origBuf[i] << offset;
			buf[i] = buf[i] ^ ((buf[i] ^ offsetedByte) & ((1 << offset) - 1));

			dword = origBuf[i];
			dword = dword << offset;
			offsetedByte = *(((u_char*)&dword) + 1);
		}

	else {

		offset = - offset;

		for (int i = 0; i < sizeBuf; i++) {

			buf[i] = origBuf[i] >> offset;
			buf[i] = buf[i] ^ ((buf[i] ^ offsetedByte) & (~(255 >> offset)));

			dword = origBuf[i] << 8;
			dword = dword >> offset;
			offsetedByte = *(u_char*)&dword;
		}
	}

	delete[] origBuf;
}

void FieldValue :: copyWithMask(u_char* modifiedBuf, UInt sizeBuf, const u_char* valueToWrite, UInt sizeValue, const FieldMask& mask) {

	check(sizeBuf >= sizeValue);

	for (int i = 0; i < sizeValue; i++) {

		u_char m = mask.getByte(sizeValue - 1 - i);

		modifiedBuf[i] = modifiedBuf[i] ^ ((modifiedBuf[i] ^ valueToWrite[i]) & m);
	}
}

void FieldValue :: changeValue(int additionValue) {

	u_int v = 0;
	u_int lv = 0;
	bool carry = false; // true - if the overflow has happened while adding to first for bytes
	int sizeValue = getSize();
	const u_char* pointerValue = !(*this);

	if (sizeValue == 0) return;

	int size = (sizeof(u_int) < sizeValue) ? sizeof(u_int) : sizeValue;

	int of = 0;
	if (sizeValue > sizeof(u_int)) of = sizeValue - sizeof(u_int);

	memcpy((u_char*)&v + (sizeof(u_int) - size), pointerValue + of, size);
	rev_order(&v, sizeof(u_int));
	lv = v;
	v += additionValue;

	if ((v < lv && additionValue > 0) || (v > lv && additionValue < 0))
		carry = true;

	rev_order(&v, sizeof(u_int));

	fill((u_char*)&v + (sizeof(u_int) - size), size, of);

	// adding to the rest of bytes (except first for bytes)

	if (carry && of != 0) {

		u_char byte = 1;

		for (int i = of - 1; i >= 0; i--) {

			v = (*this)[i];
			v += byte;
			setByte(i, (*this)[i] + *(u_char*)&v);
			byte = *((u_char*)&v + 1);
		}
	}
}

void FieldValue :: readValue(const char* valueString, DefSize sizeField) {

   string s(valueString);
   setSize(0);
   *((DBuffer*)this) = type -> getValueFromString(s, sizeField);
}

MessageString FieldValue :: getValueString(bool withTypeInfo) const {
	MessageString valueString = "None";
   valueString = type -> toString(*this, withTypeInfo);
	return valueString;
}

//void DecimalFieldValue :: readValue(const char* valueString, StresstestTextBuffer* text, int sizeField) {
//
//	StresstestTextBuffer* text1;
//
//	if (text) text1 = text;
//	else text1 = new StresstestTextBuffer();
//
//	StresstestTextBuffer :: removeEnclosingCommas(&number);
//
//	*((SizedDinamicBuffer*)this) = text1 -> readNumber(valueString, sizeField, 0);
//
//	if (!text)
//		delete text1;
//}
