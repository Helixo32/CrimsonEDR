#include <stdio.h>
#include <tchar.h>
#include <string.h>
#include <windows.h>

#include "structure.h"
#include "macro.h"
#include "utils/ipc.h"
#include "utils/peInformation.h"

#include "detection/patchAmsiByte.h"
#include "detection/patchEtwByte.h"
#include "detection/unbackedThreadStartAddress.h"
#include "detection/unbackedThreadOrigin.h"
#include "detection/ntdllUnhooking.h"
#include "detection/reflectivePe.h"
#include "detection/peStomping.h"
#include "detection/directSyscall.h"
#include "detection/searchIoc.h"
#include "hook/hookingApi.h"



/**
 * @brief      Perform all EDR checks.
 */
void LaunchEDR() {

    char                        fileName[MAX_PATH];
    char                        fullPath[MAX_PATH];
	INFORMATION_DETECTION 	    informationDetection        = { 0 };
    PVOID                       pAddress;
    SIZE_T                      regionSize;

    GetExecutableName(fileName, MAX_PATH);
    GetExecutablePath(fullPath, MAX_PATH);

    informationDetection.image_name = fileName;
    informationDetection.image_path = fullPath;
    informationDetection.pid        = GetCurrentProcessId();


    if (!PlaceHook()) {
        MessageBoxA(0, "Failed to place hook on NtWriteVirtualMemory", "CrimsonEDR", 0);
    }


    while (TRUE) {

    	if (CheckPatchByteAMSI(&informationDetection)) {
    		SendToPipe(&informationDetection);
    		TerminateProcess(GetCurrentProcess(), 0);
    	}

        if (CheckPatchByteETW(&informationDetection)) {
            SendToPipe(&informationDetection);
            TerminateProcess(GetCurrentProcess(), 0);
        
        }
        
        if (NtdllUnhooking(&informationDetection)) {
            SendToPipe(&informationDetection);
            TerminateProcess(GetCurrentProcess(), 0);
        
        }

        if (UnhookedAPI(&informationDetection)) {
            SendToPipe(&informationDetection);
            TerminateProcess(GetCurrentProcess(), 0);
        }
        
        if (PeStomping(&informationDetection)) {
            SendToPipe(&informationDetection);
            TerminateProcess(GetCurrentProcess(), 0);
        }

        if (DirectSyscall(&informationDetection)) {
            SendToPipe(&informationDetection);
            TerminateProcess(GetCurrentProcess(), 0);
        }

        if (UnbackedThreadStartAddress(&informationDetection, &pAddress, &regionSize)) {
            SendToPipe(&informationDetection);

            if (SearchIOC(&informationDetection, pAddress, regionSize)) {
                SendToPipe(&informationDetection);
                TerminateProcess(GetCurrentProcess(), 0);
            }
        }

        if (UnbackedThreadOrigin(&informationDetection, &pAddress, &regionSize)) {
            SendToPipe(&informationDetection);
            
            if (SearchIOC(&informationDetection, pAddress, regionSize)) {
                SendToPipe(&informationDetection);
                TerminateProcess(GetCurrentProcess(), 0);
            }
        }

        if (ReflectivePE(&informationDetection, &pAddress, &regionSize)) {
            SendToPipe(&informationDetection);
            
            if (SearchIOC(&informationDetection, pAddress, regionSize)) {
                SendToPipe(&informationDetection);
                TerminateProcess(GetCurrentProcess(), 0);
            }
        }

        Sleep(10 * 1000);
    }

	return;
}



BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved) {

    switch (ul_reason_for_call) {

    case DLL_PROCESS_ATTACH:

        MessageBoxA(0, "CrimsonEDR attached !", "CrimsonEDR", 0);
        LaunchEDR();

        break;

    case DLL_THREAD_ATTACH:
        break;

    case DLL_THREAD_DETACH:
        break;

    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}