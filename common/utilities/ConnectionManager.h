#ifndef CONNECTION_MANAGER_H
#define CONNECTION_MANAGER_H

#include <cstring>
#include <cstdlib>
#include <stdio.h> // TO DO fgets, to delete? better cstdio
#include <iostream>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include "Serializer.h"
#include "Deserializer.h"
#include "CryptographyManager.h"


class ConnectionManager
{
    public:
        ConnectionManager();

        void sendPacket(unsigned char*, unsigned int);

        void receivePacket(unsigned char*&);

        virtual ~ConnectionManager();

        static void printBuffer(unsigned char*, unsigned int);


    protected:
        int socket_fd;
        const unsigned int SERVER_PORT = 1234;
        const char* SERVER_ADDRESS = "127.0.0.1";
		static unsigned int message_counter;
        unsigned char* client_nonce;
        unsigned char* server_nonce;
        static const unsigned int MAX_USERNAME_SIZE = 50;
        unsigned char* signature;
        unsigned int signature_size;
		EVP_PKEY* ephemeral_private_key;	
        unsigned char* ephemeral_public_key;
        unsigned int ephemeral_public_key_size;

        
        virtual void createConnection() = 0;
        virtual void destroyConnection() = 0;
        virtual void sendHello() = 0;
        virtual void receiveHello() = 0;
        virtual unsigned int getHelloPacket(unsigned char*) = 0;
		virtual void handleHandshake() = 0;
		virtual void setSharedKey() = 0;

};
        
#endif 
