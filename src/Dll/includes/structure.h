#ifndef _STRUCTURE_H_
#define _STRUCTURE_H_

#include <windows.h>
#include <winternl.h>



#if defined(_WIN64)
#define TRAMPOLINE_SIZE     13

#elif defined(_WIN32)
#define TRAMPOLINE_SIZE     7

#endif



#define MAX_IOC_COUNT 100
#define MAX_BYTES_PER_IOC 50
#define BUFFER_SIZE 1024 // Ajustez selon la taille attendue du fichier JSON



typedef struct _INFORMATION_DETECTION {
	int 	id;
	char* 	image_name;
	char* 	image_path;
	char*   description;
	char* 	category;
	char*   detection_type;
	DWORD   pid;
	char*   process_status;
	char*   information;
} INFORMATION_DETECTION, * PINFORMATION_DETECTION;



typedef struct _HOOK_ST{
	PVOID	pFunctionToHook;
	PVOID	pFunctionToRun;
	BYTE	bOriginalBytes[TRAMPOLINE_SIZE];
	DWORD	dwOldProtection;
} HOOK_ST, *PHOOK_ST;



typedef struct _TEXT_SECTION_DATA {
    BYTE*   data;
    DWORD   size;
} TEXT_SECTION_DATA, *PTEXT_SECTION_DATA;



typedef struct _IOC {
    int bytes[MAX_BYTES_PER_IOC];
    int byteCount;
} IOC;



typedef NTSTATUS (NTAPI *pNtQueryInformationThread)(
    HANDLE ThreadHandle,
    THREADINFOCLASS ThreadInformationClass,
    PVOID ThreadInformation,
    ULONG ThreadInformationLength,
    PULONG ReturnLength
);



typedef NTSTATUS (NTAPI *pNtWriteVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    SIZE_T NumberOfBytesToWrite,
    PSIZE_T NumberOfBytesWritten
);



#endif