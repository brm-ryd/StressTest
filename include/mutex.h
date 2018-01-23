#pragma once
#ifdef WIN32
#include "windows.h"
#else
#include <pthread.h>
#include <sys/time.h>
#include <errno.h>
#endif

#include "exceptions.h"

#ifdef WIN32
#define INFINITE_WAITING INFINITE
#else
#define INFINITE_WAITING 0xffffffff
#endif

class MyEvent;

class MyMutex
{

	friend class MyEvent;

private:

#ifdef WIN32
	HANDLE handleOfMutex;
#else
	pthread_mutex_t handleOfMutex;
#endif

public:

	MyMutex();

public:

	~MyMutex(void) {

#ifdef WIN32
		CloseHandle(handleOfMutex);
#else
		int res = pthread_mutex_destroy(&handleOfMutex);
		//if (res) throw new Exception("destroying mutex :  the mutex is currently locked");
#endif
	}

public:

	/** returns true if signaled, otherwise false (if timeout) */
	bool wait(UInt timeoutInMilliseconds = INFINITE_WAITING) const;

	void release() const {

#ifdef WIN32
		if (!ReleaseMutex(handleOfMutex))
			;//throw new Exception("problems with threads synchronization : releasing the mutex : %s", winerror(0));
      // commented as it caused exception while called from ReqAndStat destructor after ctrl+break
#else
		int res = pthread_mutex_unlock((pthread_mutex_t*)&handleOfMutex);

		if (res == EINVAL)
			throw new Exception("problems with threads synchronization : signal mutex : the mutex has not been properly initialized");
		if (res == EPERM)
			throw new Exception("problems with threads synchronization : signal mutex : the calling thread does not own the mutex ('error checking' mutexes only)");

		if (res != 0) throw new Exception("problems with threads synchronization : releasing mutex : code %i", res);
#endif
	}

};


 class MyEvent
 {

 private:

#ifdef WIN32
	 HANDLE handleOfEvent;
	 HANDLE handleOfMutex;
#else
	 pthread_cond_t handleOfEvent;
	 pthread_mutex_t handleOfMutex;
#endif

 public:

	 MyEvent(bool manualReset = false);

	 ~MyEvent() {

#ifdef WIN32
		 CloseHandle(handleOfEvent);
		 //CloseHandle(handleOfMutex);
#else
		 if (pthread_cond_destroy(&handleOfEvent))
			 throw new Exception("synchronization error : destroying event");
		 if (pthread_mutex_destroy(&handleOfMutex))
			 throw new Exception("synchronization error : destroying mutex");

#endif
	 }

	 void resetEvent() {

#ifdef WIN32
		 ResetEvent(handleOfEvent);
#else
		 Test();
#endif
	 }

	 void setEvent() {

#ifdef WIN32
		 systemCheck(SetEvent(handleOfEvent));
#else
		 pthread_cond_signal(&handleOfEvent);
#endif
	 }

	 /** returns true if signaled, otherwise false (if timeout) */
	 bool wait(UInt timeoutInMilliseconds = INFINITE_WAITING, MyMutex* mutex = NULL);

	 //void blockMutex();
	 //void releaseMutex();
 };
