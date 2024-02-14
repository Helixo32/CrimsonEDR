#ifndef _REFLECTIVE_PE_H_
#define _REFLECTIVE_PE_H_

#include <windows.h>

#include "structure.h"



BOOL SearchIOC(OUT PINFORMATION_DETECTION pInformationDetection, IN PVOID pMemoryAddress, IN SIZE_T pRegionSize);

#endif