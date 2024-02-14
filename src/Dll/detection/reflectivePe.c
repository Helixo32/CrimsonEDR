#include <stdio.h>
#include <windows.h>
#include <psapi.h>

#include "macro.h"
#include "structure.h"
#include "detection/ntdllUnhooking.h"


/**
 * @brief Detects and logs information about reflectively loaded PE (Portable Executable) files in memory.
 *
 * Iterates through memory regions of the current process to find PE files loaded reflectively 
 * (i.e., not through the standard Windows loader). This detection is based on identifying memory 
 * regions that start with the 'MZ' signature of PE files and further validating those that do not 
 * correspond to modules loaded by the standard loader. It aims to identify malicious injections 
 * often used by malware for stealth and evasion.
 *
 * @param[out]  pInformationDetection   A pointer to a structure where detection information will be stored.
 * @param[out]  pMemoryAddress          Pointer to store the base address of the detected reflective PE.
 * @param[out]  pRegionSize             Pointer to store the size of the memory region occupied by the detected PE.
 * 
 * @return      Returns TRUE if a reflective PE is detected, otherwise FALSE.
 */
BOOL ReflectivePE(OUT PINFORMATION_DETECTION pInformationDetection, OUT PVOID* pMemoryAddress, OUT SIZE_T* pRegionSize) {

    char *description       		= "Reflective PE";
    char *category          		= "Injection";
    char *detection_type    		= "ReflectivePE";
    char *process_status    		= "Killed";
    char information[MAX_PATH];

    HANDLE                      hProcess                    = GetCurrentProcess();
    LPVOID                      pAddress                    = NULL;
    BYTE                        buffer[2];
    MEMORY_BASIC_INFORMATION    mbi;
    char                        moduleName[MAX_PATH];
    DWORD                       moduleNameLength;


    while (VirtualQueryEx(hProcess, pAddress, &mbi, sizeof(mbi)) != 0) {

        if (mbi.State == MEM_COMMIT) {
            if (ReadProcessMemory(hProcess, pAddress, &buffer, 2, NULL)) {

                if (buffer[0] == 'M' && buffer[1] == 'Z') {

                    moduleNameLength = GetModuleFileNameEx(hProcess, (HMODULE)pAddress, moduleName, MAX_PATH);
                    if (moduleNameLength == 0) {

                    	if (ReadModuleNameFromExportTable(hProcess, pAddress, moduleName, sizeof(moduleName))) {

                       		snprintf(information, MAX_PATH, "\n\t\t- Address     : %p\n\t\t- PE name     : %s", pAddress, moduleName);
                            
                            pInformationDetection->id               = 0;
					        pInformationDetection->description      = description;
					        pInformationDetection->category         = category;
					        pInformationDetection->detection_type   = detection_type;
					        pInformationDetection->process_status   = process_status;
					        pInformationDetection->information 		= information;

                            *pMemoryAddress = mbi.BaseAddress;
                            *pRegionSize    = mbi.RegionSize;

                       		return TRUE;
                        }
                    }
                }
            }
        }

        pAddress = pAddress + mbi.RegionSize;

    }

    return FALSE;

}