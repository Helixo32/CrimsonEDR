#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <windows.h>
#include <psapi.h>

#include "structure.h"
#include "detection/ntdllUnhooking.h"



/**
 * @brief      Gets the text section from memory.
 *
 * @param[in]  moduleName  The module name
 *
 * @return     The text section from memory.
 */
TEXT_SECTION_DATA GetTextSectionFromMemory(const char* moduleName) {
    TEXT_SECTION_DATA result = { 0 };

    HMODULE hModule = GetModuleHandleA(moduleName);
    if (!hModule) {
        return result;
    }

    IMAGE_DOS_HEADER* dosHeader = (IMAGE_DOS_HEADER*)hModule;
    IMAGE_NT_HEADERS* ntHeaders = (IMAGE_NT_HEADERS*)((BYTE*)hModule + dosHeader->e_lfanew);

    IMAGE_SECTION_HEADER* section = IMAGE_FIRST_SECTION(ntHeaders);
    for (WORD i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
        if (strncmp((char*)section[i].Name, ".text", IMAGE_SIZEOF_SHORT_NAME) == 0) {
            result.data = (BYTE*)hModule + section[i].VirtualAddress;
            result.size = section[i].Misc.VirtualSize;
            break;
        }
    }

    return result;
}



/**
 * @brief      Gets the text section from disk.
 *
 * @param[in]  filePath  The file path
 *
 * @return     The text section from disk.
 */
TEXT_SECTION_DATA GetTextSectionFromDisk(const char* filePath) {
    TEXT_SECTION_DATA result = {0, 0};
    HANDLE hFile = CreateFileA(filePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        return result;
    }

    HANDLE hFileMapping = CreateFileMapping(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
    if (!hFileMapping) {
        CloseHandle(hFile);
        return result;
    }

    LPVOID lpBaseAddress = MapViewOfFile(hFileMapping, FILE_MAP_READ, 0, 0, 0);
    if (!lpBaseAddress) {
        CloseHandle(hFileMapping);
        CloseHandle(hFile);
        return result;
    }

    IMAGE_DOS_HEADER* dosHeader = (IMAGE_DOS_HEADER*)lpBaseAddress;
    IMAGE_NT_HEADERS* ntHeaders = (IMAGE_NT_HEADERS*)((BYTE*)lpBaseAddress + dosHeader->e_lfanew);

    IMAGE_SECTION_HEADER* section = IMAGE_FIRST_SECTION(ntHeaders);
    for (WORD i = 0; i < ntHeaders->FileHeader.NumberOfSections; ++i) {
        if (strncmp((char*)section[i].Name, ".text", IMAGE_SIZEOF_SHORT_NAME) == 0) {
            result.size = section[i].SizeOfRawData;
            result.data = (BYTE*)malloc(result.size);
            if (result.data) {
                DWORD bytesRead;
                SetFilePointer(hFile, section[i].PointerToRawData, NULL, FILE_BEGIN);
                ReadFile(hFile, result.data, result.size, &bytesRead, NULL);
            }
            break;
        }
    }

    UnmapViewOfFile(lpBaseAddress);
    CloseHandle(hFileMapping);
    CloseHandle(hFile);
    return result;
}



/**
 * @brief Detects PE Stomping within the current process's memory space.
 *
 * PE Stomping is a technique used to modify the code section (typically .text section) of a loaded PE file in memory, 
 * making it different from the on-disk version. This technique can be used by malware for evasion by hiding the actual 
 * code being executed. The function iterates through memory regions, looking for PE headers ('MZ') and compares the in-memory 
 * .text section of each detected module against its on-disk counterpart. A discrepancy indicates PE Stomping has occurred.
 *
 * @param[out]  pInformationDetection   A pointer to a structure where detection information, including the name of the stomped PE file, will be stored.
 * 
 * @return      Returns TRUE if PE Stomping is detected, otherwise FALSE.
 */
BOOL PeStomping(OUT PINFORMATION_DETECTION pInformationDetection) {

	char *description       	= "PE Stomping";
    char *category          	= "Injection";
    char *detection_type    	= "PeStomping";
    char *process_status    	= "Running";
    char information[MAX_PATH];

	HANDLE                      hProcess                    = GetCurrentProcess();
    LPVOID                      pAddress                    = NULL;
    BYTE                        buffer[2];
    MEMORY_BASIC_INFORMATION    mbi;
    char                        moduleName[MAX_PATH];
    DWORD                       moduleNameLength;
    char                        moduleNames[256][MAX_PATH];
    int                         moduleCount                 = 0;


    while (VirtualQueryEx(hProcess, pAddress, &mbi, sizeof(mbi)) != 0) {

        if (mbi.State == MEM_COMMIT) {
            if (ReadProcessMemory(hProcess, pAddress, &buffer, 2, NULL)) {

                if (buffer[0] == 'M' && buffer[1] == 'Z') {

                    moduleNameLength = GetModuleFileNameEx(hProcess, (HMODULE)pAddress, moduleName, MAX_PATH);
                    if (moduleNameLength == 0) {
                        if (!ReadModuleNameFromExportTable(hProcess, pAddress, moduleName, sizeof(moduleName))) {
                            strcpy(moduleName, "Unknown");
                        }
                    }

                    if (moduleCount < 256) {
                        strncpy(moduleNames[moduleCount], moduleName, MAX_PATH - 1);
                        moduleNames[moduleCount][MAX_PATH - 1] = '\0';
                        moduleCount++;
                    }
                }

            }
        }

        pAddress = pAddress + mbi.RegionSize;

    }

    for (int i = 0; i < moduleCount; i++) {

        TEXT_SECTION_DATA textSectionMem = GetTextSectionFromMemory(ExtractFileName(moduleNames[i]));
        TEXT_SECTION_DATA textSectionDisk = GetTextSectionFromDisk(moduleNames[i]);

        if (textSectionMem.data && textSectionDisk.data && _stricmp(ExtractFileName(moduleNames[i]), "ntdll.dll") != 0) {
            if (memcmp(textSectionMem.data, textSectionDisk.data, textSectionMem.size) != 0) {
                
                snprintf(information, MAX_PATH, "\n\t\t- PE stomped 	: %s", moduleNames[i]);

                pInformationDetection->id               = 0;
		        pInformationDetection->description      = description;
		        pInformationDetection->category         = category;
		        pInformationDetection->detection_type   = detection_type;
		        pInformationDetection->process_status   = process_status;
		        pInformationDetection->information      = information;

                return TRUE;
            }
        }

    }

    return FALSE;
}