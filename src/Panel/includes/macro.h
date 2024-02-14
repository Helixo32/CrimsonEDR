#ifndef ERROR_MACROS_H
#define ERROR_MACROS_H

#include <stdio.h>
#include <windows.h>

#define PRINT_WINAPI_ERR(cApiName) printf("[!] %s failed with error: %ld\n", cApiName, GetLastError())

#endif /* ERROR_MACROS_H */
