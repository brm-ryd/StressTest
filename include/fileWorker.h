#include "exceptions.h"
#include "mstring.h"
#include "mbuffer.h"
#pragma once

/**
	Base class for all classes to work with files
*/

enum AccessToFile {
	AF_READ,
	AF_WRITE
};


class FileWorker : public DBuffer
{

public:
	MString nameOfLoadedFile;

public:
	FileWorker(void);
	~FileWorker(void);

	virtual void load(const char* filename) throw(Exception*);
	void save(const char* filename = 0) throw(Exception*);
	//const MString& getNameOfFile();
};
