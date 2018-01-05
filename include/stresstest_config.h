#ifndef CONFIG_H
#define CONFIG_H

#include "stresstest.h"
#include "stresstest_script.h"

bool check_file(char* filename);

/**
 * Provides info about program configuration.
 * Under Windows tries to read it from registry (registry.reg file is provided in distributive)
 */
class StresstestConfig {

   char* base_path;
   char* def_device;
   MString dev_type;

 public:

   StresstestConfig();
   ~StresstestConfig();

   void read ();
   const char* get_base_path();
   const char* get_def_device();
   const MString& get_device_type();
};


#endif  // CONFIG_H

