#include <stdio.h>
#include <windows.h>

#include "structure.h"
#include "detection/peStomping.h"



/**
 * @brief Detects the use of direct syscall instructions in the .text section of the current process's main module.
 *
 * Scans the .text section of the current process's main module for the presence of
 * direct syscall (on x64) or sysenter (on x32) instructions, which are indicative
 * of attempts to evade API hooking and monitoring mechanisms by directly invoking
 * system calls. The presence of such instructions in executable code may suggest
 * an attempt to perform operations in a manner that avoids detection by security software.
 *
 * @param[out]  pInformationDetection   A pointer to a structure where detection information will be stored if direct syscall instructions are found.
 * 
 * @return      Returns TRUE if direct syscall or sysenter instructions are detected, otherwise FALSE.
 */
BOOL DirectSyscall(OUT PINFORMATION_DETECTION pInformationDetection) {

	char *description       	= "Direct syscall";
    char *category          	= "Evasion";
    char *detection_type    	= "DirectSyscall";
    char *process_status    	= "Killed";
    char information[MAX_PATH];

	TEXT_SECTION_DATA textSectionMem = GetTextSectionFromMemory(NULL);

	if (textSectionMem.data == NULL || textSectionMem.size == 0) {
        return FALSE;
    }

#if defined(_WIN64)
    // syscall instruction
    BYTE badBytes[] 	= {0x0F, 0x05};
#elif defined(_WIN32)
    // sysenter instruction
    BYTE badBytes[] 	= {0x0F, 0x34};
#endif

    for (DWORD i = 0; i < textSectionMem.size - 1; i++) {
        if (memcmp(textSectionMem.data + i, badBytes, sizeof(badBytes)) == 0) {

#if defined(_WIN64)
            snprintf(information, MAX_PATH, "\n\t\t- Address 	: %p\n\t\t- Instruction 	: Syscall\n\t\t- Offset 	: %lu", GetModuleHandleA(NULL), i);
#elif defined(_WIN32)
            snprintf(information, MAX_PATH, "\n\t\t- Address 	: %p\n\t\t- Instruction 	: Sysenter\n\t\t- Offset 	: %lu", GetModuleHandleA(NULL), i);
#endif

                pInformationDetection->id               = 0;
		        pInformationDetection->description      = description;
		        pInformationDetection->category         = category;
		        pInformationDetection->detection_type   = detection_type;
		        pInformationDetection->process_status   = process_status;
		        pInformationDetection->information      = information;
            return TRUE;
        }
    }

	return FALSE;

}