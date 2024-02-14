#ifndef INJECTOR_H
#define INJECTOR_H

#include <stdio.h>
#include <windows.h>

BOOL InjectDLL(LPWSTR dllPath, DWORD pid);

#endif /* INJECTOR_H */
