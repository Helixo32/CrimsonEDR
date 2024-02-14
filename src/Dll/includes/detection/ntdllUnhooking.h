#ifndef _NTDLL_UNHOOKING_H_
#define _NTDLL_UNHOOKING_H_

#include <windows.h>

#include "structure.h"



char* ExtractFileName(char* path);
BOOL ReadModuleNameFromExportTable(IN HANDLE hProcess, IN LPVOID pBaseAddress, OUT CHAR* pModuleName, IN DWORD dwModuleNameSize);
BOOL NtdllUnhooking(OUT PINFORMATION_DETECTION pInformationDetection);

#endif