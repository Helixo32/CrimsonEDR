#include <stdio.h>
#include <string.h>
#include <windows.h>

#include "macro.h"
#include "structure.h"
#include "utils/arrayComp.h"



/**
 * @brief Checks for byte-level patches applied to the AMSI (Antimalware Scan Interface) scan buffer function.
 *
 * This function detects modifications to the AmsiScanBuffer function in amsi.dll,
 * commonly used to bypass antivirus detection. It reads the beginning bytes of
 * the AmsiScanBuffer function and compares them against known patch patterns for
 * both x86 and x64 architectures. A match indicates an evasion attempt through AMSI patching.
 *
 * @param[out]  pInformationDetection   A pointer to a structure where detection information will be stored if a patch is detected.
 * 
 * @return      Returns TRUE if a patch is detected, otherwise FALSE.
 */
BOOL CheckPatchByteAMSI(OUT PINFORMATION_DETECTION pInformationDetection) {

    char *description       = "AMSI patch by bytes detected";
    char *category          = "Evasion";
    char *detection_type    = "CheckPatchByteAMSI";
    char *process_status    = "Killed";

#if defined(_WIN64)
    int  arrayLenght  	= 6;
    BYTE patch[] 		= { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3 };                // Patch pour x64
#elif defined(_WIN32)
    int  arrayLenght  	= 8;
    BYTE patch[]        = { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC2, 0x18, 0x00 };    // Patch pour x86
#endif

    LPVOID      pAmsiAddress;
    BYTE        bytesInstruction[arrayLenght];
    SIZE_T      bytesRead;


    pAmsiAddress = GetProcAddress(GetModuleHandleA("amsi.dll"), "AmsiScanBuffer");
    if (pAmsiAddress == NULL) {
    	return FALSE;
    }

    if (ReadProcessMemory(GetCurrentProcess(), pAmsiAddress, &bytesInstruction, arrayLenght, &bytesRead) == 0){
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