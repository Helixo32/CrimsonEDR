#ifndef _EXTRACT_JSON_
#define _EXTRACT_JSON_

#include <stdio.h>
#include <windows.h>



int ExtractIDFromJSON(const char* jsonString);
int ExtractProcessStatusFromJSON(const char* jsonString, char* status, size_t maxLen);
BOOL isIDPresent(int id, const int* ids, int count);



#endif 
