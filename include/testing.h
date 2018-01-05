#ifndef _TESTING_H_
#define _TESTING_H_

#include "stresstest.h"
#include "pacbuf.h"
#include "stresstest_script.h"
#include "tcpip.h"

class Testing {

   static void checkVar(const TCHAR* var, const TCHAR* val);
   static Script* scr;

public:

   /** testing MASK command */
   static void test1();

   /** testing autoincremente */
   static void test2();

   /** testing offset */
   static void test3();

   /**
    testing appling value to field
    also BACK, POS, PASS commands
   */
   static void test4();

   static void fieldValueTest();

   /**
    * gdef, define, variables, $$ references
    */
   static void test5();

   static void runAllTests();
	
	static void testShortVarDefines();
};

#endif // _TESTING_H_
