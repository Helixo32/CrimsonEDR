#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>

#include "structure.h"



/**
 * @brief Reads the content of a specified file.
 *
 * Opens and reads the entire content of a file into a dynamically allocated buffer.
 * The buffer is null-terminated to ensure proper string handling. Handles and reports
 * errors related to file opening and memory allocation.
 *
 * @param[in]   filename    The path to the file to be read.
 * 
 * @return      A pointer to the dynamically allocated buffer containing the file's content, or NULL if an error occurred.
 */
char* ReadFileContent(IN char* filename) {
    FILE* file = fopen(filename, "r");
    if (!file) {
        return NULL;
    }

    char* buffer = (char*)malloc(BUFFER_SIZE);
    if (!buffer) {
        fclose(file);
        return NULL;
    }

    size_t bytesRead = fread(buffer, 1, BUFFER_SIZE - 1, file);
    buffer[bytesRead] = '\0';

    fclose(file);
    return buffer;
}



/**
 * @brief Parses Indicators of Compromise (IOCs) from a JSON string.
 *
 * Extracts IOCs from a provided JSON string into an array of IOC structures,
 * up to a specified maximum count. IOCs are expected to be in a specific JSON format.
 *
 * @param[in]   jsonString      The JSON string containing the IOCs.
 * @param[out]  iocs            An array of IOC structures to be filled with the parsed IOCs.
 * @param[in]   maxIocCount     The maximum number of IOCs to parse from the JSON string.
 * 
 * @return The number of IOCs successfully parsed and stored in the array.
 */
int ParseIOCs(const char* jsonString, IOC* iocs, int maxIocCount) {
    const char* pos = jsonString;
    int iocIndex = 0;
    while (*pos != '\0' && iocIndex < maxIocCount) {
        pos = strchr(pos, '[');
        if (!pos) break;

        IOC ioc = {0};
        int byteValue;
        while (*pos != ']' && *pos != '\0') {
            if (sscanf(pos, " 0x%x, ", &byteValue) == 1) {
                ioc.bytes[ioc.byteCount++] = byteValue;
            }
            pos++;
        }

        iocs[iocIndex++] = ioc;

        if (*pos != '\0') pos++;
    }
    return iocIndex;
}



/**
 * @brief Retrieves a block of memory bytes from a specified address.
 *
 * Copies a specified number of bytes from a given memory address into a newly allocated buffer.
 * This function is typically used for reading memory regions of interest.
 *
 * @param[in]   startAddress    The starting address from which to copy the bytes.
 * @param[in]   size            The number of bytes to copy.
 * 
 * @return      A pointer to the dynamically allocated buffer containing the copied bytes, or NULL if memory allocation fails.
 */
BYTE* GetMemoryBytes(const void* startAddress, size_t size) {
    BYTE* bytes = (BYTE*)malloc(size * sizeof(BYTE));
    if (bytes == NULL) {
        return NULL;
    }

    const BYTE* source = (const BYTE*)startAddress;
    for (size_t i = 0; i < size; i++) {
        bytes[i] = source[i];
    }

    return bytes;
}



/**
 * @brief Searches for Indicators of Compromise (IOCs) within a memory region and logs the detection.
 *
 * Reads the content of a specified IOC definition file (JSON format) and compares each IOC against
 * the bytes within a given memory region. If a match is found, details of the detection are logged,
 * including the matched bytes.
 *
 * @param[out]  pInformationDetection   A pointer to a structure where detection information will be stored.
 * @param[in]   pMemoryAddress          The starting address of the memory region to be searched.
 * @param[in]   regionSize              The size of the memory region to be searched.
 * 
 * @return      Returns TRUE if an IOC is detected within the memory region, otherwise FALSE.
 */
BOOL SearchIOC(OUT PINFORMATION_DETECTION pInformationDetection, IN PVOID pMemoryAddress, IN SIZE_T regionSize) {

	char *description       		= "IoC found";
    char *category          		= "Malware";
    char *detection_type    		= "SearchIOC";
    char *process_status    		= "Killed";
    char information[MAX_PATH];

	char* 	filename;
	char* 	jsonString;
	IOC 	iocs[MAX_IOC_COUNT];
	int 	iocCount;
	BYTE* 	memoryBytes;

	filename = "ioc.json";

    jsonString = ReadFileContent(filename);
    if (!jsonString) {
        MessageBoxA(0, "Failed to read JSON file", "CrimsonEDR", 0);
        return FALSE;
    }

    iocCount = ParseIOCs(jsonString, iocs, MAX_IOC_COUNT);

    memoryBytes = GetMemoryBytes(pMemoryAddress, regionSize);
    if (memoryBytes == NULL) {
    	free(jsonString);
        return FALSE;
    }

    for (int i = 0; i < iocCount; i++) {
        for (size_t j = 0; j < regionSize - iocs[i].byteCount + 1; j++) {
            BOOL match = TRUE;
            for (int k = 0; k < iocs[i].byteCount; k++) {
                if (memoryBytes[j + k] != iocs[i].bytes[k]) {
                    match = FALSE;
                    break;
                }
            }
            if (match) {

            	char matchedBytesStr[MAX_PATH] = { 0 };
			    int offset = 0;

			    for (int m = 0; m < iocs[i].byteCount; m++) {
			        if (offset < MAX_PATH - 6) {
			            offset += snprintf(matchedBytesStr + offset, MAX_PATH - offset, "0x%02x ", memoryBytes[j + m]);
			        }
			    }

			    snprintf(information, MAX_PATH, "\n\t\t- IOC number   : %d\n\t\t- Address      : %p\n\t\t- Matched Bytes: %s", i + 1, (BYTE*)pMemoryAddress + j, matchedBytesStr);
                            
                pInformationDetection->id               = 0;
		        pInformationDetection->description      = description;
		        pInformationDetection->category         = category;
		        pInformationDetection->detection_type   = detection_type;
		        pInformationDetection->process_status   = process_status;
		        pInformationDetection->information 		= information;

                free(jsonString);
                free(memoryBytes);
                return TRUE;
            }
        }
    }

    free(jsonString);
    free(memoryBytes);
	return FALSE;

}