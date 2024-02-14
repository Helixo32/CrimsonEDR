#include <stdio.h>
#include <string.h>
#include <windows.h>

#include "macro.h"
#include "structure.h"
#include "utils/crypto.h"



/**
 * @brief      Sends information to pipe.
 *
 * @param[in]  pInformationDetection  The information detection
 *
 * @return     Return TRUE if succeed, FALSE otherwise
 */
BOOL SendToPipe(PINFORMATION_DETECTION pInformationDetection) {
	HANDLE hPipe;
    DWORD dwWritten;
    char data[2048];

    pInformationDetection->id = GenerateIdFromInformation(pInformationDetection);

    snprintf(data, sizeof(data),
             "{\n\t\"id\": %d, \n\t\"image_name\": \"%s\", \n\t\"image_path\": \"%s\", "
             "\n\t\"description\": \"%s\", \n\t\"category\": \"%s\", \n\t\"detection_type\": \"%s\", "
             "\n\t\"pid\": %lu, \n\t\"process_status\": \"%s\", \n\t\"information\": \"%s\"\n}",
             pInformationDetection->id, pInformationDetection->image_name, pInformationDetection->image_path,
             pInformationDetection->description, pInformationDetection->category, pInformationDetection->detection_type,
             pInformationDetection->pid, pInformationDetection->process_status, pInformationDetection->information);

    hPipe = CreateFile(TEXT("\\\\.\\pipe\\CrimsonEDRPipe"), GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);

    if (hPipe != INVALID_HANDLE_VALUE) {
        if (!WriteFile(hPipe, data, strlen(data), &dwWritten, NULL)) {
            PRINT_WINAPI_ERR("WriteFile");
            CloseHandle(hPipe);
            return FALSE;
        }
        CloseHandle(hPipe);
    } else {
        PRINT_WINAPI_ERR("CreateFile");
        return FALSE;
    }

    return TRUE;
}