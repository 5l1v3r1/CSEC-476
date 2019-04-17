#include <windows.h>
#include <stdio.h>
#include <tchar.h>
#include <psapi.h>
#include <vector>
#include <stack>
#include <queue>

typedef std::vector<int> vi;
typedef std::pair<int, int> pii;
typedef std::vector<pii> vii;
const size_t MAX_PROCS = 1024;

void WeGetOneProcess(DWORD processID) {
	char szProcessName[MAX_PATH] = "<unknown>";
	HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processID);

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

	printf("%s  (PID: %u)\n", szProcessName, processID);
	CloseHandle(hProcess);
}

void WeGetPriv() {
	HANDLE hToken = NULL;
	TOKEN_PRIVILEGES tokenPriv;
	LUID luidDebug;

	if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_READ, &hToken)) {
		if (LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luidDebug)) {
			tokenPriv.PrivilegeCount = 1;
			tokenPriv.Privileges[0].Luid = luidDebug;
			tokenPriv.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
			if (!AdjustTokenPrivileges(hToken, FALSE, &tokenPriv, 0, NULL, NULL)) {
				printf("AdjustTokenPrivileges failed: %x\n", GetLastError());
			}
		}
	}
}

int WeGetProcesses(void) {
	DWORD aProcesses[MAX_PROCS], cbNeeded, cProcesses;

	if (!EnumProcesses(aProcesses, sizeof(aProcesses), &cbNeeded)) {
		printf("EnumProcesses failed: %x\n", GetLastError());
		return 1;
	}

	cProcesses = cbNeeded / sizeof(DWORD);

	for (unsigned int i = 0; i < cProcesses; i++) {
		if (aProcesses[i] != 0) {
			WeGetOneProcess(aProcesses[i]);
		}
	}

	return 0;
}

int main(void) {
	WeGetPriv();
	WeGetProcesses();
}