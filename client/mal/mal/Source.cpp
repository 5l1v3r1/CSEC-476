#include <windows.h>
#include <stdio.h>
#include <tchar.h>
#include <psapi.h>
#define PSAPI_VERSION 1
// To ensure correct resolution of symbols, add Psapi.lib to TARGETLIBS
// and compile with -DPSAPI_VERSION=1

void PrintProcessNameAndID(DWORD processID) {
	char szProcessName[MAX_PATH] = "<unknown>";

	// Get a handle to the process.
	HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processID);

	// Get the process name.
	if (NULL != hProcess) {
		HMODULE hMod;
		DWORD cbNeeded;

		if (EnumProcessModules(hProcess, &hMod, sizeof(hMod), &cbNeeded)) {
			if (!GetModuleBaseNameA(hProcess, hMod, szProcessName, sizeof(szProcessName) / sizeof(char))) {
				printf("GetModuleBaseName failed: %x\n", GetLastError());
			}
		}
		else {
			printf("EnumProcessModules failed: %x\n", GetLastError());
		}
	}
	else {
		printf("OpenProcess failed: %x\n", GetLastError());
	}

	// Print the process name and identifier.
	printf("%s  (PID: %u)\n", szProcessName, processID);

	// Release the handle to the process.
	CloseHandle(hProcess);
}

int main(void) {
	// Get the list of process identifiers.

	DWORD aProcesses[1024], cbNeeded, cProcesses;
	unsigned int i;

	// Obtain privilege

	HANDLE hToken = NULL;
	TOKEN_PRIVILEGES tokenPriv;
	LUID luidDebug;
	if (FALSE != OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_READ, &hToken)) {
		if (FALSE != LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luidDebug)) {
			tokenPriv.PrivilegeCount = 1;
			tokenPriv.Privileges[0].Luid = luidDebug;
			tokenPriv.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
			if (!AdjustTokenPrivileges(hToken, FALSE, &tokenPriv, 0, NULL, NULL)) {
				printf("AdjustTokenPrivileges failed: %x\n", GetLastError());
			}
		}
	}

	if (!EnumProcesses(aProcesses, sizeof(aProcesses), &cbNeeded)) {
		printf("EnumProcesses failed: %x\n", GetLastError());
		return 1;
	}

	// Calculate how many process identifiers were returned.
	cProcesses = cbNeeded / sizeof(DWORD);

	// Print the name and process identifier for each process.
	for (i = 0; i < cProcesses; i++) {
		if (aProcesses[i] != 0) {
			PrintProcessNameAndID(aProcesses[i]);
		}
	}

	return 0;
}