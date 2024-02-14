#include <stdio.h>
#include <string.h>
#include <windows.h>

#include "macro.h"
#include "structure.h"
#include "utils/arrayComp.h"



/**
 * @brief Checks for byte-level patches applied to the ETW (Event Tracing for Windows) event writing function.
 *
 * This function detects modifications to the EtwEventWrite function in ntdll.dll, typically used
 * to evade event logging. It reads the beginning bytes of the EtwEventWrite function and compares
 * them against known patch patterns for both x86 and x64 architectures. A match indicates an evasion
 * attempt through ETW patching.
 *
 * @param[out]  pInformationDetection   A pointer to a structure where detection information will be stored if a patch is detected.
 * 
 * @return      Returns TRUE if a patch is detected, otherwise FALSE.
 */
BOOL CheckPatchByteETW(OUT PINFORMATION_DETECTION pInformationDetection) {

    char *description       = "ETW patch by bytes detected";
    char *category          = "Evasion";
    char *detection_type    = "CheckPatchByteETW";
    char *process_status    = "Killed";

#if defined(_WIN64)
    int  arrayLenght  	= 1;
    BYTE patch[] 		= { 0xC3 };                // Patch pour x64
#elif defined(_WIN32)
    int  arrayLenght  	= 4;
    BYTE patch[]        = { 0xC2, 0x14, 0x00, 0x00 };    // Patch pour x86
#endif

    LPVOID      pEtwEventWriteAddress;
    BYTE        bytesInstruction[arrayLenght];
    SIZE_T      bytesRead;


    pEtwEventWriteAddress = GetProcAddress(GetModuleHandleA("ntdll.dll"), "EtwEventWrite");
    if (pEtwEventWriteAddress == NULL) {
    	PRINT_WINAPI_ERR("GetProcAddress");
    	return FALSE;
    }

    if (ReadProcessMemory(GetCurrentProcess(), pEtwEventWriteAddress, &bytesInstruction, arrayLenght, &bytesRead) == 0){
    	PRINT_WINAPI_ERR("ReadProcessMemory");
    	return FALSE;
    }

    if (areArraysEqual(patch, bytesInstruction, arrayLenght)) {

        pInformationDetection->id               = 0;
        pInformationDetection->description      = description;
        pInformationDetection->category         = category;
        pInformationDetection->detection_type   = detection_type;
        pInformationDetection->process_status   = process_status;
        pInformationDetection->information      = "(null)";

    	return TRUE;
    }

    return FALSE;

}