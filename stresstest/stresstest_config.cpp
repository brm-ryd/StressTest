//---------------------------------------------------------------------------

#include "stdafx.h"
#include "stresstest_config.h"

#define PROG_KEY  "Software\\Stresstest"


StresstestConfig :: StresstestConfig () {

   base_path = 0;
   def_device = 0;   
}

StresstestConfig :: ~StresstestConfig () {

   if (base_path) free(base_path);
   if (def_device) free(def_device);
}

const char* StresstestConfig :: get_base_path() {

	#ifndef WIN32	
	return STRESSTEST_PREFIX;
	#endif
   return base_path;
}

const char* StresstestConfig :: get_def_device() {

   return def_device;
}


const MString& StresstestConfig :: get_device_type() {

   return dev_type;
}


#ifdef WIN32
void StresstestConfig :: read() {

   HKEY key;
   DWORD size;
   LONG res;

   if (ERROR_SUCCESS != RegOpenKeyEx(HKEY_CURRENT_USER, PROG_KEY, 0, KEY_READ, &key)) {

      throw new Exception("opening registry key 'HKEY_CURRENT_USER\\%s'", PROG_KEY);    
   }

   size = 0;
   res = ERROR_SUCCESS;
   RegQueryValueEx(key, "default_adapter", 0, NULL, NULL, &size);
   if (size) {

      def_device = (char*)malloc(size+1);
      memCheck(def_device);
      res = RegQueryValueEx(key, "default_adapter", 0, NULL, (LPBYTE)def_device, &size);
   }
   if (res != ERROR_SUCCESS || !size) {

         throw new Exception("reading field 'default_adapter'");
   }

   size = 0;
   res = ERROR_SUCCESS;
   RegQueryValueEx(key, "dir", 0, NULL, NULL, &size);
   if (size) {

      base_path = (char*)malloc(size+1);
      memCheck(def_device);
      res = RegQueryValueEx(key, "dir", 0, NULL, (LPBYTE)base_path, &size);
   }
   if (res != ERROR_SUCCESS || !size) {

         throw new Exception("reading field 'dir'");         
   }

   char dev_type_str[20];
   size = 19;
   if (ERROR_SUCCESS != RegQueryValueEx(key, "dev_type", 0, NULL, (LPBYTE)dev_type_str, &size)) {

         throw new Exception("reading field 'dev_type'");         
   }

   dev_type = dev_type_str;
//   if (!strCaseCompare(dev_type_str,"ethernet")) dev_type = DT_ETH;
//   if (!strCaseCompare(dev_type_str,"ip")) dev_type = DT_IP;
//   if (!strCaseCompare(dev_type_str,"tcp")) dev_type = DT_TCP;

   RegCloseKey(key);   
}
#else
void StresstestConfig :: read () {

}
#endif

