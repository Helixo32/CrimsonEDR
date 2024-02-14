#ifndef _HOOKING_API_H_
#define _HOOKING_API_H_

#include <windows.h>

#include "structure.h"

BOOL UnhookedAPI(OUT PINFORMATION_DETECTION pInformationDetection);
BOOL PlaceHook();

#endif