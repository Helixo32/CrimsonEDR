#include <stdio.h>
#include <windows.h>

#include "macro.h"


/**
 * @brief      Injects a DLL into a process specified by PID.
 *
 * @param      dllPath  The dll path
 * @param[in]  pid      The pid
 *
 * @return     Return TRUE if succeed, FALSE otherwise.
 */
BOOL InjectDLL(IN LPWSTR dllPath, IN DWORD pid) {

	HANDLE 					hProcess;
	HANDLE  				hThread;
	DWORD  					dwSizeToWrite 			= lstrlenW(dllPath) * sizeof(WCHAR);
	SIZE_T 					lpNumberOfBytesWritten;
	PVOID 					pAddress;
	LPVOID				 	pLoadLibraryW;

	DWORD  					threadId;

	pLoadLibraryW = GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryW");
	if (pLoadLibraryW == NULL) {
		PRINT_WINAPI_ERR("GetProcAddress");
		return FALSE;
	}

	hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	if (hProcess == NULL) {
		PRINT_WINAPI_ERR("OpenProcess");
		return FALSE;
	}

	pAddress = VirtualAllocEx(hProcess, NULL, dwSizeToWrite, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (pAddress == NULL) {
		PRINT_WINAPI_ERR("VirtualAllocEx");
		return FALSE;
	}

	if (!WriteProcessMemory(hProcess, pAddress, dllPath, dwSizeToWrite, &lpNumberOfBytesWritten) || lpNumberOfBytesWritten != dwSizeToWrite) {
		PRINT_WINAPI_ERR("WriteProcessMemory");
		return FALSE;
	}

	hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pLoadLibraryW, pAddress, 0, &threadId);
	if (hThread == NULL) {
		PRINT_WINAPI_ERR("CreateRemoteThread");
		return FALSE;
	}

	CloseHandle(hProcess);

	return TRUE;

}	