#ifndef CONNECTION_MANAGER_H
#define CONNECTION_MANAGER_H

#include <iostream>
#include <unistd.h>
#include <arpa/inet.h>
#include <cstring>
#include <cstdlib>
#include <stdio.h> // TO DO: fgets, to delete? better cstdio
#include <sys/socket.h>
#include <netinet/in.h>
#include <experimental/filesystem>
#include "CryptographyManager.h"
#include "Serializer.h"
#include "Deserializer.h"

class ConnectionManager
{
    public:
        ConnectionManager();


        //closeSocket();

        virtual ~ConnectionManager();

        static void printBuffer(unsigned char*, unsigned int);
		static unsigned int areBuffersEqual(unsigned char*, unsigned int,
											unsigned char*, unsigned int);


    protected:
        int socket_fd;
        const int SERVER_PORT = 1234;
        const char* SERVER_ADDRESS = "127.0.0.1";
		unsigned int message_counter = 0;
        unsigned char* client_nonce;
        unsigned char* server_nonce;
        static const unsigned int MAX_USERNAME_SIZE = 50;
        unsigned char* signature;
        unsigned int signature_size;
		EVP_PKEY* ephemeral_private_key;	
        unsigned char* ephemeral_public_key;
        unsigned int ephemeral_public_key_size;
		unsigned char* shared_key;

		unsigned char* getMessageToSend(unsigned char*, unsigned int&);     
        void sendPacket(unsigned char*, unsigned int);
        void receivePacket(unsigned char*&);
		unsigned char* parseReceivedMessage(Deserializer, unsigned int&);

		// TO DO: insert in a file of constants
		const unsigned int UPLOAD_OPERATION_CODE = 0;
		const unsigned int DOWNLOAD_OPERATION_CODE = 1;
		const unsigned int DELETE_OPERATION_CODE = 2;
		const unsigned int LIST_OPERATION_CODE = 3;
		const unsigned int RENAME_OPERATION_CODE = 4;
		const unsigned int LOGOUT_OPERATION_CODE = 5;

		// TO DO: insert in a file of constants
		const char* LIST_MESSAGE = "LIST";
		const char* ACK_MESSAGE = "ACK";		

        virtual void createConnection() = 0;
        virtual void destroyConnection() = 0;
        virtual void sendHello() = 0;
        virtual void receiveHello() = 0;
        virtual unsigned int getHelloPacket(unsigned char*) = 0;
		virtual void handleHandshake() = 0;
		virtual void setSharedKey() = 0;


};
        
#endif 
