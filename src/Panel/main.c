#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>

#include "macro.h"
#include "injector/injector.h"
#include "utils/extractJson.h"

#define MAX_IDS 2048



/**
 * @brief Main entry point for the CrimsonEDR tool.
 *
 * This program displays a startup logo and processes command-line arguments to monitor
 * a specific process identified by a PID and to inject a DLL into it. It supports two 
 * command-line arguments: `-p` to specify the PID of the process to monitor, and `-d` to 
 * specify the path to the DLL to be injected. The function enters a monitoring loop where 
 * it listens for detection events from the injected DLL through a named pipe. Each event 
 * is processed to extract and log unique detection IDs and to handle process status updates.
 * If the monitored process is marked as "Killed", the user is prompted to enter a new PID 
 * for monitoring. The program handles errors gracefully, including incorrect command-line 
 * arguments, DLL injection failures, and issues with named pipe communication.
 *
 * @param argc The number of command-line arguments.
 * @param argv The command-line arguments.
 * @return int Returns 0 on successful execution and termination, 1 on errors.
 */
int main(int argc, char *argv[]) {

	int     detectionId;
	int 	detectionIDs[MAX_IDS];
	int 	detectionIDCount;
	char 	processStatus[50];
	DWORD 	pid;
	char* 	dllPathANSI;
	WCHAR   dllPathW[MAX_PATH];
	HANDLE 	hPipe;
	char  	buffer[2048];
	DWORD 	dwRead;
	BOOL 	connected;
	char* 	logo =
	"   _____                                  ______ _____  _____  \n"
	"  / ____|    (_)                         |  ____|  __ \\|  __ \\ \n"
	" | |     _ __ _ _ __ ___  ___  ___  _ __ | |__  | |  | | |__) |\n"
	" | |    | '__| | '_ ` _ \\/ __|/ _ \\| '_ \\|  __| | |  | |  _  / \n"
	" | |____| |  | | | | | | \\__ \\ (_) | | | | |____| |__| | | \\ \\ \n"
	"  \\_____|_|  |_|_| |_| |_|___/\\___/|_| |_|______|_____/|_|  \\_\\\n\n";

	printf("%s", logo);

	// Browse all command line arguments
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-p") == 0) {
            if (i + 1 < argc) {
                pid = atoi(argv[i + 1]);
            } else {
                fprintf(stderr, "[-] Option -p requires a value.\n");
                return 1;
            }
        } else if (strcmp(argv[i], "-d") == 0) {
            if (i + 1 < argc) {
                dllPathANSI = argv[i + 1];
            } else {
                fprintf(stderr, "[-] Option -d requires a value..\n");
                return 1;
            }
        }
    }

    MultiByteToWideChar(CP_UTF8, 0, dllPathANSI, -1, dllPathW, MAX_PATH);

    while (TRUE) {

	    printf("\n\n[i] PID to monitor 	: %lu\n", pid);
	    printf("[i] DLL path 		: %s\n\n", dllPathANSI);

	    if (!InjectDLL(dllPathW, pid)) {
	    	printf("[-] Error : Failed to inject DLL\n\n");
	    	return 1;
	    }
		
		printf("[i] Waiting for events ...\n\n");

		while (TRUE) {

			hPipe = CreateNamedPipe(
				TEXT("\\\\.\\pipe\\CrimsonEDRPipe"),
				PIPE_ACCESS_DUPLEX,
				PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
				PIPE_UNLIMITED_INSTANCES,
				2048,
				2048,
				NMPWAIT_USE_DEFAULT_WAIT,
				NULL
			);
			if (hPipe == INVALID_HANDLE_VALUE) {
				PRINT_WINAPI_ERR("CreateNamedPipe");
				return 1;
			}

			connected = ConnectNamedPipe(hPipe, NULL);

			if (connected) {
				while (ReadFile(hPipe, buffer, sizeof(buffer) - 1, &dwRead, NULL) != FALSE) {
					buffer[dwRead] = '\0';

					if (detectionIDCount < MAX_IDS) {
					    detectionId = ExtractIDFromJSON(buffer);
					    if (detectionId != -1 && !isIDPresent(detectionId, detectionIDs, detectionIDCount)) {
					        // If the ID is not -1 and not already present, add it to the table
					        detectionIDs[detectionIDCount++] = detectionId;
					        printf("[!] Alert : \n%s\n\n\n", buffer);
					    }
					} else {
					    printf("ID storage limit reached.\n");
					    return 0;
					}
				}
			} else {
				PRINT_WINAPI_ERR("ConnectNamedPipe");
			}

			CloseHandle(hPipe);

			if (ExtractProcessStatusFromJSON(buffer, processStatus, sizeof(processStatus)) == 0) {
		        if (strcmp(processStatus, "Killed") == 0) {

		        	printf("==========================================================\n\n");
		        	printf("[#] Please enter a new PID to monitor : ");
				    if (scanf("%lu", &pid) != 1) {
				        printf("[-] Error : Invalid input\n\n");
				        continue;
				    }
		        	break;
		        
		        }
		    }

		}
	}

	return 0;

}