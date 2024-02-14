#ifndef _REFLECTIVE_PE_H_
#define _REFLECTIVE_PE_H_

#include <windows.h>

#include "structure.h"



BOOL ReflectivePE(OUT PINFORMATION_DETECTION pInformationDetection, OUT PVOID* pMemoryAddress, OUT SIZE_T* pRegionSize);

#endif