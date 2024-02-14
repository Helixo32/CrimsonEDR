#include <stdio.h>
#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <dbghelp.h>

#include "macro.h"
#include "structure.h"
#include "detection/unbackedThreadStartAddress.h"



/**
 * @brief Identifies threads originating from unbacked memory regions using their stack trace.
 *
 * Analyzes the stack trace of each thread in the current process to determine if the origin
 * of the thread's execution is from an unbacked memory region, suggesting potential code injection
 * or other unauthorized modifications. This function iterates through all threads, captures
 * their stack traces, and examines the symbols associated with each stack frame. If the final symbol
 * in the stack trace is "Unknown", indicating the absence of a valid backing module, it gathers
 * and returns information about the thread, including the base address and size of the memory region being executed.
 *
 * @param[out] pInformationDetection 	Structure to store detection information if an unbacked thread origin is found.
 * @param[out] pMemoryAddress 			Pointer to store the base address of the memory region associated with the unbacked thread origin.
 * @param[out] pRegionSize 				Pointer to store the size of the memory region associated with the unbacked thread origin.
 * 
 * @return Returns TRUE if an unbacked thread origin is detected, otherwise FALSE.
 */
BOOL UnbackedThreadOrigin(OUT PINFORMATION_DETECTION pInformationDetection, OUT PVOID* pMemoryAddress, OUT SIZE_T* pRegionSize) {

	char *description       	= "Unbacked thread origin";
    char *category          	= "Injection";
    char *detection_type    	= "UnbackedThreadOrigin";
    char *process_status    	= "Running";
    char information[MAX_PATH];


	HANDLE  					hSnapshot;
	THREADENTRY32 				te;
	HANDLE  					hProcess;
	HANDLE  					hThread;
	CONTEXT 					context;
	STACKFRAME64 				frame;
	DWORD64  					dwOffset;
	PVOID 						pAddress;
	MEMORY_BASIC_INFORMATION  	mbi;
	CHAR symbols[128][MAX_SYM_NAME];
	int symbolCount = 0;


	te.dwSize = sizeof(te);
	hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (hSnapshot == INVALID_HANDLE_VALUE) {
		PRINT_WINAPI_ERR("CreateToolhelp32Snapshot");
    	return FALSE;
	}

	if (Thread32First(hSnapshot, &te)) {
		while (Thread32Next(hSnapshot, &te)) {
			if (te.th32OwnerProcessID == GetCurrentProcessId()) {
				symbolCount = 0;

				hThread 		= OpenThread(THREAD_ALL_ACCESS, FALSE, te.th32ThreadID);
				hProcess 		= OpenProcess(PROCESS_ALL_ACCESS, FALSE, GetCurrentProcessId());

				SymInitialize(hProcess, NULL, TRUE);

				context.ContextFlags = CONTEXT_FULL;
				if (!GetThreadContext(hThread, &context)) {
					PRINT_WINAPI_ERR("GetThreadContext");
    				return FALSE;
				}

				frame.AddrPC.Offset 	= context.Rip;
                frame.AddrPC.Mode 		= AddrModeFlat;
                frame.AddrStack.Offset 	= context.Rsp;
                frame.AddrStack.Mode 	= AddrModeFlat;
                frame.AddrFrame.Offset 	= context.Rbp;
                frame.AddrFrame.Mode 	= AddrModeFlat;

                int i = 0;
                while (TRUE) {
                	if (!StackWalk64(IMAGE_FILE_MACHINE_AMD64, hProcess, hThread, &frame, &context, NULL, SymFunctionTableAccess64, SymGetModuleBase64, NULL)) {
                		break;
                	}

                	if (frame.AddrPC.Offset == 0 || frame.AddrFrame.Offset == 0) {
				        break;
				    }

					char buffer[sizeof(SYMBOL_INFO) + MAX_SYM_NAME * sizeof(WCHAR)] = { 0 };
					PSYMBOL_INFO symbol 	= (PSYMBOL_INFO)buffer;
					symbol->SizeOfStruct 	= sizeof(SYMBOL_INFO);
					symbol->MaxNameLen 		= MAX_SYM_NAME;

					if (SymFromAddr(hProcess, frame.AddrPC.Offset, &dwOffset, symbol)) {
						strncpy(symbols[symbolCount], symbol->Name, MAX_SYM_NAME - 1);
				        symbols[symbolCount][MAX_SYM_NAME - 1] = '\0'; // Assurer la terminaison de la chaîne
				        symbolCount++;
					} else {
						strncpy(symbols[symbolCount], "Unknown", MAX_SYM_NAME - 1);
				        symbols[symbolCount][MAX_SYM_NAME - 1] = '\0'; // Assurer la terminaison de la chaîne
				        symbolCount++;
					}

					i += 1;
                }

                if (symbolCount > 0 && strcmp(symbols[symbolCount - 1], "Unknown") == 0) {

                	pAddress = (PVOID)frame.AddrPC.Offset;
					if (!VirtualQueryEx(hProcess, pAddress, &mbi, sizeof(mbi))) {
						PRINT_WINAPI_ERR("VirtualQueryEx");
    					return FALSE;
					}

					snprintf(information, MAX_PATH, "\n\t\t- Thread 	: %d\n\t\t- Address 	: %p\n\t\t- Size 		: %d", te.th32ThreadID, mbi.BaseAddress, mbi.RegionSize);

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