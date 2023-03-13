#ifndef CONNECTION_MANAGER_H
#define CONNECTION_MANAGER_H

#include <iostream>
#include <unistd.h>
#include <arpa/inet.h>
#include <cstring>
#include <cstdlib>
#include <stdio.h> // fgets, to delete? better cstdio
#include <sys/socket.h>
#include <netinet/in.h>
#include "CryptographyManager.h"
#include "Serializer.h"
#include "Deserializer.h"

class ConnectionManager
{
    public:
        ConnectionManager();

        void sendPacket(unsigned char*, uint32_t);

        void receivePacket(unsigned char*&);

        //closeSocket();

        virtual ~ConnectionManager();

    protected:
        int socket_fd;
        const int SERVER_PORT = 1234;
        const char* SERVER_ADDRESS = "127.0.0.1";
        char* nonce;

		void printBuffer(unsigned char*, int);
        
        virtual void createConnection() = 0;

        virtual void destroyConnection() = 0;


};
        
#endif 
