#ifndef _FIELDMASK_H_
#define _FIELDMASK_H_

class SresstestTextBuffer;

#include "stresstest.h"
#include "messagebuff.h"

/*
	Class FieldMask.
	mask of field from protocol header.
	used when bounds of field area are not coincide with byte bounds.
	Mask is hexadecimal number. Each bit from mask corresponds to bit from field's bytes (bytes that overlap with field's area)
	Not null bit indicates that the corresponding bit of field's bytes belongs to field, null bit - not.
	if some bit doesnt belong to field its value will not change while writing value of field.
	If mask's size is less than field's size then null bits will be added to the left of mask.
   Mask is initialy set to correspond to the whole field.

   Example: if a field has size = 2 bytes and occupies 4th and 5th bytes (from the start of packet's buffer) then
 *     mask = 0x1 means then field will actually occupy the lowest bit of 5th byte
 *     mask = 0x100 means then field will actually occupy the lowest bit of 4th byte
 *     mask = 0xff means then field will actually occupy the whole 5th byte
 *


*/
class FieldMask : public DBuffer {

	bool filled_whole;


public:

	FieldMask();
	FieldMask(u_int value);

	bool operator==(const FieldMask& otherMask) const {

		if (filled_whole != otherMask.filled_whole) return false;
		if (filled_whole) return true;
		return (*(DBuffer*)this).isTheSameContent(*(DBuffer*)&otherMask);
	}

	/**
	 * sets value
	 * \param value string that must represent a hex number
	 * \param text if NULL then will be used AnettestTextBuffer will default parameters
	 */
	void setValue(
		const char* value
		);

	/**
	 * sets value
	 */
	void setValue(u_int value);

	/**
	 * sets value
	*/
	void setRawvalue(u_char* value,
						  int size);

	/**
	 * returns the byte of mask with specified index (0 - rightmost byte).
	 * if index is more than the size of mask then returns 0
	 */
	u_char getByte(u_int index) const;

	//FieldMask& operator=(const FieldMask& sourceMask);

	void setWholeField() {
		filled_whole = true;
	}

	bool isWholeField() const {
		return filled_whole;
	}
};

#endif //_FIELDMASK_H_
