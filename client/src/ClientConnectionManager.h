#ifndef CLIENT_CONNECTION_MANAGER_H
#define CLIENT_CONNECTION_MANAGER_H
#include "../../common/utilities/ConnectionManager.h"

class ClientConnectionManager: public ConnectionManager
{
    public:
        ClientConnectionManager();
        ~ClientConnectionManager();

        void sendHello();
        void receiveHello();
		void sendFinalHandshakeMessage();		

    private:
        const unsigned int MAX_USERNAME_SIZE = 50;
        const char* PRIVATE_KEY_FILENAME_SUFFIX = "_key.pem";
        const char* PRIVATE_KEY_FILENAME_PREFIX = "client/files/";
        const unsigned int MAX_PRIVATE_KEY_FILENAME_SIZE = 
                                strlen(PRIVATE_KEY_FILENAME_PREFIX) + 
                                MAX_USERNAME_SIZE +
                                strlen(PRIVATE_KEY_FILENAME_SUFFIX) + 1;

        // TO DO: change this constant
        const unsigned int MAX_FINAL_HANDSHAKE_MESSAGE_SIZE = 2048;


        unsigned char* serialized_private_key;
        unsigned int serialized_private_key_size;
		
        char username[MAX_USERNAME_SIZE];
        
        // username_size_size + nonce_size_size + max_username_size + nonce_size
        const unsigned int MAX_HELLO_SIZE = 
                    sizeof(MAX_USERNAME_SIZE) 
                    + MAX_USERNAME_SIZE 
                    + sizeof(CryptographyManager::getNonceSize()) 
                    + CryptographyManager::getNonceSize();

        void createConnection();
        void destroyConnection();
        void obtainUsername();
        unsigned int getHelloPacket(unsigned char*);
        unsigned int getFinalHandshakeMessage(unsigned char*);
        

};

#endif
