#ifndef CLIENT_CONNECTION_MANAGER_H
#define CLIENT_CONNECTION_MANAGER_H
#include "../common/utilities/ConnectionManager.h"

class ClientConnectionManager: public ConnectionManager
{
    public:
        ClientConnectionManager();
        ~ClientConnectionManager();

        void sendHello();

        // connect();

    private:
        static const int MAX_USERNAME_SIZE = 50;
		
        char username[MAX_USERNAME_SIZE];
        
        //username_size_size + nonce_size_size + max_username_size + nonce_size
        int MAX_CLIENT_HELLO_SIZE = sizeof(uint16_t) + sizeof(uint16_t) 
					+ MAX_USERNAME_SIZE + CryptographyManager::getNonceSize();

        void createConnection();
        void destroyConnection();
        int getHelloPacket(unsigned char*);
        void obtainUsername();
};

#endif
