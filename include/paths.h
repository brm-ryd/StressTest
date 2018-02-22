#ifndef PATHS_H
#define PATHS_H

#include "stresstest.h"
#include "exceptions.h"
#include "messagestring.h"

/** returns true if path exists */
bool checkPath(const char* filename);

/**
	Class Path.
	Works with paths where to search headers and traces.
*/

class Paths {

	vector<MessageString> paths;

public:

   Paths();
   ~Paths();

	/** adds path */
	void add_path(MessageString* newpath) throw(Exception*) {

		/**addnewstr(newpath, strlen(newpath), false); */
		bool found = false;
		vector<MessageString>::iterator it = paths.begin();
		for (; it != paths.end(); it++)
		{
			if (it -> compare(*newpath) == 0)
			{
				found = true;
				break;
			}
		}

		if (!found)
			paths.push_back(*newpath);
	}

	/**
    searches the given file in paths and returns its full path,
	 for each path also seraches in headers, samples, traces folders
	 and appends .fws postfix to the name of file
   */
   MessageString& search(MessageString& name, const char* filename);
};

#endif
