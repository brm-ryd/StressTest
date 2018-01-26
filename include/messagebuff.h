#ifndef _DINAMICBUFFER_H_
#define _DINAMICBUFFER_H_

#ifdef WIN32
#include <stdio.h>
#include <malloc.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <io.h>
#include <fcntl.h>
#else
#include <stdio.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#endif

typedef unsigned int uint;
typedef unsigned char u_char;

#include "exceptions.h"
#include "mstring.h"

#define DATA_NOT_FOUND ((UInt)(-1))


// for objects derived from messagebuff
#define FORBID_COPING_BUFFER(x)\
	x(const x&) : messagebuff(0) { Test(); }\
	void operator=(const x&) { Test(); }

// for objects derived from DynamicRecords
#define FORBID_COPING(x)\
	x(const x&) : DynamicRecords(0, 0) { Test(); }\
	void operator=(const x&) { Test(); }


#define DEFINE_COPY_CONSTRUCTOR(x) x(const x& s) { *this = s; }


class messagebuff {

private:

	bool blockModification;
   uint allocatedSize;
	/** when dynamic buffer grows, its size may only be changed by defined step */
	uint sizeOfAllocationStep;

protected:

	void** managedData;

public:

protected:

	/** allocates dynamic memory not less than given size (in bytes) */
	void checkAllocation(uint neededSizeOfAllocation);

public:

	messagebuff(
		void** managedData // pointer to pointer to dynamicly allocated data
		);
   ~messagebuff();

	/** returns the pointer to allocated memory,
		after call to this method the object is restricted in use,
		till call to 'unblock'.
	*/
	void* getPointer() {

		blockModification = true;
		return *managedData;
	}

	void unblock() { blockModification = false; }

	virtual const UChar& operator[](uint index) {

		check(!blockModification);
		check(index < allocatedSize);
		return ((UChar*)(*managedData))[index];
	}

	void setSizeOfAllocationStep(uint sizeOfAllocationStep) {

		userCheck(sizeOfAllocationStep);
		this -> sizeOfAllocationStep = sizeOfAllocationStep;
	}

	int getSizeOfAllocationStep() { return sizeOfAllocationStep; }

	messagebuff& operator=(const messagebuff& sourceBuffer) {

		check(!blockModification);

		sizeOfAllocationStep = sourceBuffer.sizeOfAllocationStep;
		checkAllocation(sourceBuffer.allocatedSize);
		memcpy(*managedData, *(sourceBuffer.managedData), sourceBuffer.allocatedSize);

		return *this;
	}

	void freeMemory() {

		check(!blockModification);

		userCheck(managedData);

		if (*managedData) :: free(*managedData);
		*managedData = 0;
		allocatedSize = 0;
	}
};


/**
	Dynamic buffer with associated size.
	Size may be less or equal to the really allocated size.

*/


class DBuffer : public messagebuff {

protected:

	u_char* buffer;
	uint currentSize;

public:

	/** true - newly allocated memory will be filled by zeros */
	bool fillByZero;

   /** true - operator[] will not automatically allocate new memory
							  when index exceeds the current size of buffer,
							  instead exception OutOfBufferBorders will raise
   */
	bool fixedSize;
private:

	void checkSize(uint newSize) {

		checkAllocation(newSize);

		if (fillByZero && newSize > currentSize)
			memset(buffer + currentSize, 0, newSize - currentSize);
	}

public:

	static void test();

	DBuffer(const DBuffer& s) : messagebuff ((void**)&buffer) { *this = s; }
	DBuffer() : messagebuff ((void**)&buffer) {

		fillByZero = false;
		fixedSize = false;
		buffer = 0;

		currentSize = 0;
		//nameSource = "unknown source";
	}

	~DBuffer() {

	}

	bool isTheSameContent(const DBuffer& otherBuf) {

		if (currentSize != otherBuf.getSize()) return false;
		if (currentSize == 0) return true;
		if (memcmp(buffer, !otherBuf, currentSize)) return false;
		else return true;
	}

	DBuffer& operator=(const DBuffer& sourceBuf) {

		*(messagebuff*)this = (const messagebuff&)sourceBuf;

		currentSize = sourceBuf.currentSize;
		//nameSource = sourceBuf.nameSource;
		fixedSize = sourceBuf.fixedSize;
		fillByZero = sourceBuf.fillByZero;

		return *this;
	}

	virtual const UChar& operator[](uint index) {

		if (index >= currentSize) {

			if (!fixedSize) {

				checkSize(index + 1);
				currentSize = index + 1;
				//memset((u_char*)(*managedData) + currentSize, 0, index - currentSize + 1);
			}
			else {

				throw new OutOfBufferBorders();
			}
		}

		return this -> messagebuff :: operator[](index);
	}

	/**
	 fills buffer by given 'value' from 'index' to 'index + count - 1'
	 expands
	*/
	void setByte(UInt index, UChar value, UInt count = 1) {

		if (index + count - 1>= currentSize) {

			if (!fixedSize) {

				checkSize(index + count);
				currentSize = index + count;
				//memset((u_char*)(*managedData) + currentSize, 0, index - currentSize + 1);
			}
			else {

				throw new OutOfBufferBorders();
			}
		}

		if (count == 1)
			buffer[index] = value;
		else
			memset(buffer + index, value, count);
	}

	const u_char* operator!() const;

	virtual u_char getChar(uint index) const {

		if (index >= currentSize) {

			throw new OutOfBufferBorders();
		}

		return buffer[index];
	}

	/**
	 method fill,
	 copies content of given source buffer to object's buffer
	*/
	virtual void fill(const void* sourceBuf, uint sizeSourceBuf, uint startPosInObjectBuffer = 0) {

		checkSize(sizeSourceBuf + startPosInObjectBuffer);

		if (sizeSourceBuf + startPosInObjectBuffer > currentSize)
			currentSize = sizeSourceBuf + startPosInObjectBuffer;

		if (buffer && sizeSourceBuf) memcpy(buffer + startPosInObjectBuffer, sourceBuf, sizeSourceBuf);
	}

	/**
	 method get,
	 copies content of object's buffer to given destination buffer
	*/
	void get(void* destBuffer, uint numBytesToCopy, uint startPosInObjectBuffer = 0) const {

		check(numBytesToCopy + startPosInObjectBuffer <= currentSize);
		if (buffer) memcpy(destBuffer, buffer + startPosInObjectBuffer, numBytesToCopy);
	}

	void setSize(uint newSize) { checkSize(newSize); currentSize = newSize; }
	uint getSize() const { return currentSize; }

	void setZero() {

		memset(buffer, 0, currentSize);
	}

	/**void loadFromFile(const TCHAR* filename) throw(Exception*); */

	void clear() { currentSize = 0; }

	void release() {

		clear();
		freeMemory();
	}

	/**
	 return the start position of first found entry,
	 the found entry will always be contained in [startPosInInternalBuffer, stopPosInInternalBuffer] piece
	*/
	UInt search(
		const DBuffer& soughtData,
		UInt startPosInInternalBuffer = 0,
		UInt stopPosInInternalBuffer = (UInt)-1 // -1 means search to end
		) const;

	/**
	 return the start position of first found entry,
	 the found entry will always be contained in [stopPosInInternalBuffer, startPosInInternalBuffer] piece
	*/
	UInt searchBack(
		const DBuffer& soughtData,
		UInt startPosInInternalBuffer = 0,
		UInt stopPosInInternalBuffer = (UInt)-1 // -1 means search to beginning
		) const;
};


/*******************************************************
**************** class DynamicRecords ******************
*******************************************************/

class DynamicRecords : public messagebuff
{

private:

	int recordSize;
	uint num_records;

protected:

	DynamicRecords(void** managedArray, int recordSize);

	/** sets the new number of records, deleting records or allocating new memory */
	void setNumRecords(int numRecordsInArray);

	void addOneRecord() { setNumRecords(num_records + 1); }

	/** deletes the record with given number,
		"notSafe" because befor deleting the record ,
		some pointers must be release if this record contain such pointers
	*/
	void deleteRecord_notSafe(int numRecordToDelete);

	/** inserts the new record, shifting other records (with given number and lower) */
	void insertRecord(int numRecordToMove);

public:

	inline uint numRecords() const { return num_records; }

	/* each derived class must implement this method due to avoid problems
		explained in description for 'deleteRecord_notSafe'
		*/
	virtual void deleteRecord(int numberRecordToDelete) = 0;

	DynamicRecords& operator=(const DynamicRecords& sourceRecords) {

		*(messagebuff*)this = (const messagebuff&)sourceRecords;

		recordSize = sourceRecords.recordSize;
		num_records = sourceRecords.num_records;

		return *this;
	}
};

#endif // _DYNAMICBUFFER_H_
