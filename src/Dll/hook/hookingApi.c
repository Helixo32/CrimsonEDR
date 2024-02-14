#include <stdio.h>
#include <stdint.h>
#include <windows.h>

#include <macro.h>
#include <structure.h>
#include <NtApi.h>



#if defined(_WIN64)
#define TRAMPOLINE_SIZE     13

#elif defined(_WIN32)
#define TRAMPOLINE_SIZE     7

#endif



HOOK_ST sHookNtWriteVirtualMemory = { 0 };



/**
 * @brief      Initializes the hook structure.
 *
 * @param[in]  pFunctionToHook  The function to hook
 * @param[in]  pFunctionToRun   The function to run
 * @param[out] pHook            The hook structure
 *
 * @return     Return TRUE if succeed, FALSE otherwise.
 */
BOOL InitializeHookStruct(IN PVOID pFunctionToHook, IN PVOID pFunctionToRun, OUT PHOOK_ST pHook) {

    pHook->pFunctionToHook  = pFunctionToHook;
    pHook->pFunctionToRun   = pFunctionToRun;

    memcpy(pHook->bOriginalBytes, pFunctionToHook, TRAMPOLINE_SIZE);

    if (!VirtualProtect(pFunctionToHook, TRAMPOLINE_SIZE, PAGE_EXECUTE_READWRITE, &pHook->dwOldProtection)) {
        PRINT_WINAPI_ERR("VirtualProtect");
        return FALSE;
    }

    return TRUE;

}



/**
 * @brief Installs a function hook by injecting a trampoline into the target function.
 *
 * This function creates and installs a trampoline for either 32-bit or 64-bit applications. 
 * The trampoline redirects execution from the original function (specified in the PHOOK_ST structure) 
 * to a new function (also specified in the PHOOK_ST structure). For 64-bit applications, it uses 
 * `mov r10, address` followed by `jmp r10` instructions. For 32-bit applications, it uses 
 * `mov eax, address` followed by `jmp eax`. This method allows for the interception and redirection 
 * of function calls dynamically at runtime.
 *
 * @param[in]  pHook  Pointer to the HOOK_ST structure containing pointers to the original function 
 *                    and the new function to which the execution will be redirected.
 *                    
 * @return Returns TRUE upon successful installation of the hook.
 */
BOOL InstallHook(IN PHOOK_ST pHook) {

#if defined(_WIN64)
    uint8_t uTrampoline[] = {
        0x49, 0xBA, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov r10, pFunctionToRun
        0x41, 0xFF, 0xE2                                            // jmp r10
    };

    uint64_t uPatch = (uint64_t)(pHook->pFunctionToRun);
    memcpy(&uTrampoline[2], &uPatch, sizeof(uPatch));

#elif defined(_WIN32)
    uint8_t     uTrampoline[] = {
        0xB8, 0x00, 0x00, 0x00, 0x00,     // mov eax, pFunctionToRun
        0xFF, 0xE0                        // jmp eax
    };

    uint32_t uPatch = (uint32_t)(pHook->pFunctionToRun);
    memcpy(&uTrampoline[1], &uPatch, sizeof(uPatch));

#endif

    memcpy(pHook->pFunctionToHook, uTrampoline, sizeof(uTrampoline));

    return TRUE;

}



/**
 * @brief      Removes a hook.
 *
 * @param[in]  pHook  The hook structure
 *
 * @return     Return TRUE if succeed, FALSE otherwise.
 */
BOOL RemoveHook(IN PHOOK_ST pHook) {

    DWORD   dwOldProtection;

    memcpy(pHook->pFunctionToHook, pHook->bOriginalBytes, TRAMPOLINE_SIZE);
    memset(pHook->bOriginalBytes, '\0', TRAMPOLINE_SIZE);

    if (!VirtualProtect(pHook->pFunctionToHook, TRAMPOLINE_SIZE, pHook->dwOldProtection, &dwOldProtection)) {
        PRINT_WINAPI_ERR("VirtualProtect");
        return FALSE;
    }

    pHook->pFunctionToHook  = NULL;
    pHook->pFunctionToRun   = NULL;
    pHook->dwOldProtection  = NULL;

    return TRUE;

}



/**
 * @brief      Detects whether a hook placed on an api has been deleted.
 *
 * @param[out] pInformationDetection  The information detection
 *
 * @return     Return TRUE if unhooked, FALSE otherwise.
 */
BOOL UnhookedAPI(OUT PINFORMATION_DETECTION pInformationDetection) {

    char *description           = "Unhooked API";
    char *category              = "Evasion";
    char *detection_type        = "UnhookedAPI";
    char *process_status        = "Killed";
    char information[MAX_PATH];

    BYTE    bytesInstruction[TRAMPOLINE_SIZE];
    SIZE_T  bytesRead;

    if (!ReadProcessMemory(GetCurrentProcess(), sHookNtWriteVirtualMemory.pFunctionToHook, &bytesInstruction, TRAMPOLINE_SIZE, &bytesRead)) {
        PRINT_WINAPI_ERR("VirtualProtect");
        return FALSE;
    }

    if (memcmp(sHookNtWriteVirtualMemory.bOriginalBytes, bytesInstruction, TRAMPOLINE_SIZE) == 0) {

        snprintf(information, MAX_PATH, "\n\t\t- API    : NtWriteVirtualMemory");

        pInformationDetection->id               = 0;
        pInformationDetection->description      = description;
        pInformationDetection->category         = category;
        pInformationDetection->detection_type   = detection_type;
        pInformationDetection->process_status   = process_status;
        pInformationDetection->information      = information;

        return TRUE;
    }

    return FALSE;

}



/**
 * @brief Replaces the standard NtWriteVirtualMemory function with a hooked version to monitor memory write operations.
 *
 * This function temporarily removes an existing hook (if any), calls the original NtWriteVirtualMemory function
 * to perform the intended memory write operation, and then re-applies the hook. This allows for monitoring
 * and logging memory write operations by intercepting calls to NtWriteVirtualMemory, without disrupting the normal
 * operation of the function.
 *
 * @param[in] ProcessHandle Handle to the process in which memory will be written.
 * @param[in] BaseAddress Pointer to the base address in the specified process where memory will be written.
 * @param[in] Buffer Pointer to the buffer containing the data to be written into the specified process's memory.
 * @param[in] NumberOfBytesToWrite Number of bytes to be written to the specified process's memory.
 * @param[out] NumberOfBytesWritten Pointer to a variable that receives the number of bytes actually written.
 *
 * @return NTSTATUS code representing the outcome of the operation, indicating success or failure.
 */
NTSTATUS NTAPI HookedNtWriteVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, SIZE_T NumberOfBytesToWrite, PSIZE_T NumberOfBytesWritten) {

    if (!RemoveHook(&sHookNtWriteVirtualMemory)) {
        return "0x00000080";
    }

    pNtWriteVirtualMemory MyNtWriteVirtualMemory = (pNtWriteVirtualMemory)GetProcAddress(GetModuleHandle("ntdll.dll"), "NtWriteVirtualMemory");
    NTSTATUS status = MyNtWriteVirtualMemory(ProcessHandle, BaseAddress, Buffer, NumberOfBytesToWrite, NumberOfBytesWritten);

    //SearchIoc();

    if (!PlaceHook()) {
        MessageBoxA(0, "Failed to place hook on NtWriteVirtualMemory", "CrimsonEDR", 0);
    }

    return status;
}



/**
 * @brief Sets up and installs a hook on the NtWriteVirtualMemory function.
 *
 * This function initializes a hook structure for NtWriteVirtualMemory,
 * then installs the hook to intercept calls to NtWriteVirtualMemory.
 * The hooking mechanism allows monitoring and potentially modifying the behavior
 * of memory write operations in other processes, which can be used for security,
 * debugging, or system analysis purposes.
 *
 * @return Returns TRUE if the hook was successfully placed, FALSE if the operation failed.
 */
BOOL PlaceHook() {

    PVOID addressNtWriteVirtualMemory = (PVOID)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtWriteVirtualMemory");
    
    if (!InitializeHookStruct(addressNtWriteVirtualMemory, &HookedNtWriteVirtualMemory, &sHookNtWriteVirtualMemory)) {
        return FALSE;
    }

    if (!InstallHook(&sHookNtWriteVirtualMemory)) {
        return FALSE;
    }

    return TRUE;

}
