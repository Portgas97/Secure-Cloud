#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<unistd.h>
#include<errno.h>
#include<sys/types.h>
#include<sys/socket.h>
#include<sys/wait.h>
#include<netinet/in.h>
#include<arpa/inet.h>
#include<signal.h>


// parameters
#define SERVER_PORT 3490     // the port users will be connecting to
#define BACKLOG_QUEUE 10      // how many pending connections queue will be hold



/* 
#ifndef REMOTE_CONTROL_SERVR
#define REMOTE_CONTROL_SERVR

#include <WinSock2.h>
#include <windows.h>
#include <ws2tcpip.h>
#include <stdlib.h>
#include <iostream>

#pragma comment (lib, "Ws2_32.lib")

// size of our buffer
#define DEFAULT_BUFLEN 512
// port to connect sockets through 
#define DEFAULT_PORT "80"

class RemoteControlServer {
public:
	RemoteControlServer();
	~RemoteControlServer();
	static int sendMessage(SOCKET curSocket, char * message, int messageSize);
	static int receiveMessage(SOCKET curSocket, char * buffer, int bufSize);
};

#endif // !REMOTE_CONTROL_SERVR
*/