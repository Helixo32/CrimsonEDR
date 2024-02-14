#ifndef _UNBACKED_THREAD_START_ADDRESS_H_
#define _UNBACKED_THREAD_START_ADDRESS_H_

#include <windows.h>

#include "structure.h"



BOOL UnbackedThreadStartAddress(OUT PINFORMATION_DETECTION pInformationDetection, OUT PVOID* pMemoryAddress, OUT SIZE_T* pRegionSize);

#endif