#ifndef CONNECTION_MANAGER_H
#define CONNECTION_MANAGER_H

#include "UtilityManager.h"

class ConnectionManager
{
    public:
        ConnectionManager();
        virtual ~ConnectionManager();

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

		unsigned char* getMessageToSend(unsigned char*, unsigned int&, 
														unsigned int = 0);     
        void sendPacket(unsigned char*, unsigned int);
        void receivePacket(unsigned char*&);
		unsigned char* parseReceivedMessage(Deserializer, unsigned int&);
		int sendFileContent(std::string, const char*);
		std::string getRequestCommand();
		unsigned char* getMessagePlaintext(unsigned char*, unsigned int&);
		
		// operation messages
		const char* UPLOAD_MESSAGE = "UPLOAD";
		const char* LAST_UPLOAD_MESSAGE = "LAST_UPLOAD";
		const char* DOWNLOAD_MESSAGE = "DOWNLOAD";
		const char* LAST_DOWNLOAD_MESSAGE = "LAST_DOWNLOAD";
		const char* DELETE_MESSAGE = "DELETE";
		const char* LIST_MESSAGE = "LIST";
		const char* RENAME_MESSAGE = "RENAME";
		const char* LOGOUT_MESSAGE = "LOGOUT";
		const char* ACK_MESSAGE = "ACK";		
		const char* ERROR_MESSAGE = "ERROR";

		const unsigned int CHUNK_SIZE = 10; // 500 KB

        virtual void createConnection() = 0;
        virtual void destroyConnection() = 0;
        virtual void sendHello() = 0;
        virtual void receiveHello() = 0;
        virtual void getHelloPacket(unsigned char*) = 0;
		virtual void handleHandshake() = 0;
		virtual void setSharedKey() = 0;


};
        
#endif 
