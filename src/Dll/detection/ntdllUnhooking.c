#include <stdio.h>
#include <ctype.h>
#include <windows.h>
#include <psapi.h>

#include "macro.h"
#include "structure.h"



/**
 * @brief Extracts the file name from a given path.
 *
 * This function takes a file path and returns the file name portion by locating the last backslash character 
 * and returning the substring that follows it. If no backslash is found, the original path is returned, 
 * indicating that it already represents a file name.
 *
 * @param[in]   path    The file path from which to extract the file name.
 * 
 * @return      A pointer to the beginning of the file name in the original path string.
 */
char* ExtractFileName(char* path) {
    char* lastSlash = strrchr(path, '\\');
    if (lastSlash) {
        return lastSlash + 1;
    }
    return path;
}



/**
 * @brief Reads the name of a module from its export table in memory.
 *
 * Attempts to read the name of a module directly from its export table in memory of a given process. This is useful 
 * for identifying modules even when standard API calls might fail or return inaccurate information, particularly in 
 * the context of analyzing potentially manipulated or maliciously injected code.
 *
 * @param[in]   hProcess The handle to the process containing the module.
 * @param[in]   pBaseAddress The base address of the module in the process's memory.
 * @param[out]  pModuleName Buffer to store the module's name.
 * @param[in]   dwModuleNameSize The size of the buffer provided for the module name.
 * 
 * @return      Returns TRUE if the module name was successfully read, otherwise FALSE.
 */
BOOL ReadModuleNameFromExportTable(IN HANDLE hProcess, IN LPVOID pBaseAddress, OUT CHAR* pModuleName, IN DWORD dwModuleNameSize) {
    DWORD peOffset;
    IMAGE_NT_HEADERS64 peHeader;
    IMAGE_EXPORT_DIRECTORY exportDir;

    if (pModuleName == NULL) return FALSE;

    if (!ReadProcessMemory(hProcess, (LPBYTE)pBaseAddress + 0x3C, &peOffset, sizeof(peOffset), NULL)) {
        return FALSE;
    }

    if (!ReadProcessMemory(hProcess, (LPBYTE)pBaseAddress + peOffset, &peHeader, sizeof(peHeader), NULL)) {
        return FALSE;
    }

    if (peHeader.Signature != IMAGE_NT_SIGNATURE) {
        return FALSE;
    }

    DWORD exportDirRVA = peHeader.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if (!ReadProcessMemory(hProcess, (LPBYTE)pBaseAddress + exportDirRVA, &exportDir, sizeof(exportDir), NULL)) {
        return FALSE;
    }

    if (!ReadProcessMemory(hProcess, (LPBYTE)pBaseAddress + exportDir.Name, pModuleName, dwModuleNameSize, NULL)) {
        return FALSE;
    }

    pModuleName[dwModuleNameSize - 1] = '\0';
    for (DWORD i = 0; i < dwModuleNameSize; i++) {
        if (pModuleName[i] == '\0') break;
        if (!isprint((unsigned char)pModuleName[i])) {
            return FALSE;
        }
    }

    return TRUE;
}



/**
 * @brief Detects and reports multiple instances of ntdll.dll loaded in the current process's memory.
 *
 * Iterates through the memory of the current process to find all committed memory regions starting with the 'MZ' header, 
 * indicative of a PE file. For each detected PE file, it attempts to identify it as an instance of ntdll.dll. If more 
 * than one instance is found, this is reported as a potential unhooking or evasion attempt since multiple instances 
 * of ntdll.dll should not normally be present.
 *
 * @param[out]  pInformationDetection   A pointer to a structure where detection information will be stored if multiple instances of ntdll.dll are detected.
 * 
 * @return      Returns TRUE if multiple instances of ntdll.dll are detected, otherwise FALSE.
 */
BOOL NtdllUnhooking(OUT PINFORMATION_DETECTION pInformationDetection) {

    char *description       = "Multiple ntdll.dll detected";
    char *category          = "Evasion";
    char *detection_type    = "NtdllUnhooking";
    char *process_status    = "Killed";

    HANDLE                      hProcess                    = GetCurrentProcess();
    LPVOID                      pAddress                    = NULL;
    BYTE                        buffer[2];
    MEMORY_BASIC_INFORMATION    mbi;
    char                        moduleName[MAX_PATH];
    DWORD                       moduleNameLength;
    char                        moduleNames[256][MAX_PATH];
    int                         moduleCount                 = 0;
    int                         ntdllCount                  = 0;


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
        char* moduleName = ExtractFileName(moduleNames[i]);
        if (_stricmp(moduleName, "ntdll.dll") == 0) {
            ntdllCount++;
        }
    }

    if (ntdllCount > 1) {

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