#ifndef _ERROR_MACROS_H_
#define _ERROR_MACROS_H_

#include <stdio.h>
#include <windows.h>

#define PRINT_WINAPI_ERR(cApiName) printf("[!] %s failed with error: %ld\n", cApiName, GetLastError())

#endif /* ERROR_MACROS_H */
