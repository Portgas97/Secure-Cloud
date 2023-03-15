#ifndef SERVER_CONNECTION_MANAGER_H
#define SERVER_CONNECTION_MANAGER_H
#include "../common/utilities/ConnectionManager.h"

class ServerConnectionManager: public ConnectionManager 
{
    public:
        ServerConnectionManager();
		ServerConnectionManager(int);
        ~ServerConnectionManager();

        void acceptRequest();


    private:
		const char* CERTIFICATE_FILENAME = "../files/Server_cert.pem";
        const char* PRIVATE_KEY_FILENAME = "../files/Server_key.pem";

        unsigned char* certificate;
        EVP_PKEY* ephemeral_private_key;
        unsigned char* ephemeral_public_key;
        unsigned int ephemeral_public_key_size;
        unsigned char* signed_message;
        unsigned int signed_message_size;

        //username_size_size + nonce_size_size + max_username_size + nonce_size
        const unsigned int MAX_HELLO_SIZE = 
                    sizeof(CryptographyManager::getNonceSize()) +
                    sizeof(MAX_USERNAME_SIZE) +
					MAX_USERNAME_SIZE + CryptographyManager::getNonceSize();

        const unsigned int MAX_CONNECTIONS = 10;
        void createConnection();
        void destroyConnection();
        void serveClient(int);
        void sendHello();
        char* receiveHello();
        unsigned int getHelloPacket(unsigned char*);        
        
};

#endif
