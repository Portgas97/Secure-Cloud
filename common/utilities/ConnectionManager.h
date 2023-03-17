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

        static void printBuffer(unsigned char*, unsigned int);


    protected:
        int socket_fd;
        const int SERVER_PORT = 1234;
        const char* SERVER_ADDRESS = "127.0.0.1";
        const static int NONCE_SIZE = 16;
        char client_nonce[NONCE_SIZE];
        char server_nonce[NONCE_SIZE];
        const unsigned int MAX_USERNAME_SIZE = 50;
        char username[MAX_USERNAME_SIZE];
        unsigned char* signature;
        unsigned int signature_size;
        unsigned char* ephemeral_public_key;
        unsigned int ephemeral_public_key_size;

        
        virtual void createConnection() = 0;
        virtual void destroyConnection() = 0;
        virtual void sendHello() = 0;
        virtual void receiveHello() = 0;
        virtual unsigned int getHelloPacket(unsigned char*) = 0;

};
        
#endif 
