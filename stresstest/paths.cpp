//#include "stdafx.h"
#include "paths.h"
#pragma hdrstop

Paths :: Paths () {

	add_path(new MString("."));
}

Paths :: ~Paths () {

	paths.clear();
}

MString& Paths :: search(MString& name, const char* filename) {

	name = filename;

	if (!checkPath(filename)) {

		name.append(".fws");

		if (!checkPath(!name)) {

			// searches in all folders from list

			vector<MString>::iterator it = paths.begin();
			for (; it != paths.end(); it++)
			{
				name = *it;

				name.append("/");
				name.append(filename);
				if (checkPath(!name)) break;
				name.append(".fws");
				if (checkPath(!name)) break;

				name = *it;
				name.append("/headers/");
				name.append(filename);
				if (checkPath(!name)) break;
				name.append(".fws");
				if (checkPath(!name)) break;

				name = *it;
				name.append("/samples/");
				name.append(filename);
				if (checkPath(!name)) break;
				name.append(".fws");
				if (checkPath(!name)) break;

				name = *it;
				name.append("/traces/");
				name.append(filename);
				if (checkPath(!name)) break;
				name.append(".pcap");
				if (checkPath(!name)) break;

				name.erase();
			}
		}
	}

   return name;
}


#ifdef WIN32
bool checkPath(const char* filename) {

   DWORD res;
   res = GetFileAttributes(filename);
   if (res == (DWORD) -1) return 0;
   else return 1;
}
#else
bool checkPath(const char* filename) {

   struct stat st;
   if (-1 == stat(filename,&st)) return 0;
   else return 1;
}
#endif
