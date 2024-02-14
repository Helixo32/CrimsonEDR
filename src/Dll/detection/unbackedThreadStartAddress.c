#include <stdio.h>
#include <string.h>
#include <windows.h>
#include <winternl.h>
#include <ntstatus.h>
#include <tlhelp32.h>
#include <psapi.h>

#include "macro.h"
#include "structure.h"
#include "NtApi.h"



/**
 * @brief      Gets the thread start address.
 *
 * @param[in]  hProcess  The process
 * @param[in]  hThread   The thread
 *
 * @return     The thread start address.
 */
PVOID GetThreadStartAddress(IN HANDLE hProcess, IN HANDLE hThread) {

	NTSTATUS 	status;
	HMODULE 	hNtdll;
	HANDLE  	hDupHandle;
	PVOID  		pStartAddress;


	hNtdll = GetModuleHandleA("ntdll.dll");
	if (hNtdll == NULL) {
		PRINT_WINAPI_ERR("GetModuleHandleA");
    	return NULL;
	}

	pNtQueryInformationThread NtQueryInformationThread = (pNtQueryInformationThread)GetProcAddress(hNtdll, "NtQueryInformationThread");
	if (!NtQueryInformationThread) {
		PRINT_WINAPI_ERR("GetProcAddress");
    	return NULL;
	}

	if (!DuplicateHandle(hProcess, hThread, hProcess, &hDupHandle, THREAD_QUERY_INFORMATION, FALSE, 0)) {
		PRINT_WINAPI_ERR("DuplicateHandle");
    	return NULL;
	}

	status = NtQueryInformationThread(hDupHandle, 9, &pStartAddress, sizeof(PVOID), NULL);
	if (status != STATUS_SUCCESS) {
		PRINT_WINAPI_ERR("NtQueryInformationThread");
    	return NULL;
	}

	CloseHandle(hDupHandle);

	return pStartAddress;

}



/**
 * @brief Checks if a given address within a process is backed by a module.
 *
 * This function examines the memory region at a specified address in a process to determine
 * if it is backed by a module. It uses VirtualQueryEx to retrieve information about the memory
 * region and GetMappedFileNameA to check if there is a module name associated with it.
 * It is typically used to identify if a thread's start address is within an expected module
 * or if it might be operating from an unexpected or "unbacked" memory region, potentially indicating
 * injection or other malicious activity.
 *
 * @param[in] hProcess The handle to the process containing the address.
 * @param[in] pAddress The address within the process to check.
 * 
 * @return Returns TRUE if the memory at the address is backed by a module or
 * 		   if the memory state or type indicates it should not be considered "unbacked". Otherwise, returns FALSE.
 */
BOOL ThreadHaveBackedModule(IN HANDLE hProcess, IN PVOID pAddress) {

	MEMORY_BASIC_INFORMATION  	mbi;
	TCHAR 						buffer[512];
	DWORD 						length;


	if (VirtualQueryEx(hProcess, pAddress, &mbi, sizeof(MEMORY_BASIC_INFORMATION)) == 0) {
		PRINT_WINAPI_ERR("VirtualQueryEx");
    	return TRUE;
	}

	if (mbi.State == MEM_COMMIT || mbi.Type == MEM_PRIVATE) {
		length = GetMappedFileNameA(hProcess, pAddress, buffer, sizeof(buffer));
		if (length > 0) {
			return TRUE;
		} else {
			return FALSE;
		}
	}

	return TRUE;

}



/**
 * @brief Identifies threads within the current process that start from unbacked memory regions.
 *
 * This function iterates through threads of the current process to find any that start from memory regions
 * not backed by any module, indicating potential code injection or other forms of malicious activity.
 * It uses a combination of toolhelp snapshots, thread enumeration, and memory querying to perform this detection.
 * Detected threads and their start addresses are logged, and information about the detection is populated
 * in an INFORMATION_DETECTION structure.
 *
 * @param[out] pInformationDetection 	A pointer to a structure where detection information will be stored.
 * @param[out] pMemoryAddress 			Output pointer to store the start address of the detected thread.
 * @param[out] pRegionSize 				Output pointer to store the size of the memory region associated with the detected thread.
 * 
 * @return Returns TRUE if an unbacked thread start address is found, otherwise FALSE.
 */
BOOL UnbackedThreadStartAddress(OUT PINFORMATION_DETECTION pInformationDetection, OUT PVOID* pMemoryAddress, OUT SIZE_T* pRegionSize) {

	char *description       	= "Unbacked thread start address";
    char *category          	= "Injection";
    char *detection_type    	= "UnbackedThreadStartAddress";
    char *process_status    	= "Running";
    char information[MAX_PATH];

	THREADENTRY32 				te;
	HANDLE 						hThreadSnap;
	HANDLE 						hThread;
	PVOID 						pThreadAddress;
	HANDLE  					hProcess 		= GetCurrentProcess();
	MEMORY_BASIC_INFORMATION 	mbi;


	te.dwSize 	= sizeof(THREADENTRY32);
	hThreadSnap	= CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (hThreadSnap == INVALID_HANDLE_VALUE) {
		PRINT_WINAPI_ERR("CreateToolhelp32Snapshot");
    	return FALSE;
	}

	if (Thread32First(hThreadSnap, &te)) {
		while (Thread32Next(hThreadSnap, &te)) {
			if (te.th32OwnerProcessID == GetCurrentProcessId()) {
				
				hThread = OpenThread(THREAD_QUERY_INFORMATION, FALSE, te.th32ThreadID);
				if (hThread == NULL) {
					PRINT_WINAPI_ERR("OpenThread");
    				return FALSE;
				}

				pThreadAddress = GetThreadStartAddress(hProcess, hThread);
				if (pThreadAddress == NULL) {
					return FALSE;
				}

				if (!ThreadHaveBackedModule(hProcess, pThreadAddress)) {

					if (VirtualQueryEx(hProcess, pThreadAddress, &mbi, sizeof(mbi)) == 0) {
						PRINT_WINAPI_ERR("VirtualQueryEx");
    					return FALSE;
					}

					snprintf(information, MAX_PATH, "\n\t\t- Thread 	: %d\n\t\t- Address 	: %p", te.th32ThreadID, pThreadAddress);

					pInformationDetection->id               = 0;
			        pInformationDetection->description      = description;
			        pInformationDetection->category         = category;
			        pInformationDetection->detection_type   = detection_type;
			        pInformationDetection->process_status   = process_status;
			        pInformationDetection->information 		= information;

			        *pMemoryAddress = mbi.BaseAddress;
			        *pRegionSize 	= mbi.RegionSize;

					return TRUE;
				}
			}
		}
	}

	return FALSE;

}