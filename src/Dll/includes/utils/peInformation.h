#ifndef PE_INFORMATION_H
#define PE_INFORMATION_H

#include <windows.h>

void GetExecutablePath(OUT char* pBuffer, IN DWORD size);
void GetExecutableName(OUT char* pBuffer, IN DWORD size);

#endif