#ifndef CLIENT_CONNECTION_MANAGER_H
#define CLIENT_CONNECTION_MANAGER_H
#include "../../common/utilities/ConnectionManager.h"

class ClientConnectionManager: public ConnectionManager
{
    public:
        ClientConnectionManager();
        ~ClientConnectionManager();

        // connect();

        void sendHello();
        void receiveHello();

    private:
        static const unsigned int MAX_USERNAME_SIZE = 50;
		
        char username[MAX_USERNAME_SIZE];
        
        //username_size_size + nonce_size_size + max_username_size + nonce_size
        const unsigned int MAX_HELLO_SIZE = 
                    sizeof(CryptographyManager::getNonceSize()) +
                    sizeof(MAX_USERNAME_SIZE) +
					MAX_USERNAME_SIZE + CryptographyManager::getNonceSize();

        void createConnection();
        void destroyConnection();
        unsigned int getHelloPacket(unsigned char*);
        void obtainUsername();
};

#endif
