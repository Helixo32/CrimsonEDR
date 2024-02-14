#ifndef _UNBACKED_THREAD_ORIGIN_H_
#define _UNBACKED_THREAD_ORIGIN_H_

#include <windows.h>

#include "structure.h"



BOOL UnbackedThreadOrigin(OUT PINFORMATION_DETECTION pInformationDetection, OUT PVOID* pMemoryAddress, OUT SIZE_T* pRegionSize);

#endif