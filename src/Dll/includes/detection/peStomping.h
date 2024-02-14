#ifndef _PE_STOMPING_H_
#define _PE_STOMPING_H_

#include <stdio.h>
#include <windows.h>

#include "structure.h"



TEXT_SECTION_DATA GetTextSectionFromMemory(const char* moduleName);
BOOL PeStomping(OUT PINFORMATION_DETECTION pInformationDetection);



#endif