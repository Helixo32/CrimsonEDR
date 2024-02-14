#include <stdio.h>
#include <windows.h>

#include "macro.h"



/**
 * @brief      Gets the executable path.
 *
 * @param[out] pBuffer  The buffer
 * @param[in]  size     The size
 */
void GetExecutablePath(OUT char* pBuffer, IN DWORD size) {
    if (GetModuleFileName(NULL, pBuffer, size) == 0) {
        PRINT_WINAPI_ERR("GetModuleFileName");
        pBuffer[0] = '\0';
    }
}



/**
 * @brief      Gets the executable name.
 *
 * @param[out] pBuffer  The buffer
 * @param[in]  size     The size
 */
void GetExecutableName(OUT char* pBuffer, IN DWORD size) {
    char path[MAX_PATH];
    if (GetModuleFileName(NULL, path, MAX_PATH) != 0) {
        char* fileName = strrchr(path, '\\');
        if (fileName != NULL) {
            strncpy(pBuffer, fileName + 1, size);
            pBuffer[size - 1] = '\0'; 
        } else {
            strncpy(pBuffer, path, size);
            pBuffer[size - 1] = '\0';
        }
    } else {
        PRINT_WINAPI_ERR("GetModuleFileName");
        pBuffer[0] = '\0';
    }
}