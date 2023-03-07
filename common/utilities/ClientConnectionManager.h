#include "ConnectionManager.h"

class ClientConnectionManager: public ConnectionManager
{
    public:
        ClientConnectionManager();

        void sendHello();

        // connect();

    private:
        static const int MAX_USERNAME_SIZE = 50;
        char username[MAX_USERNAME_SIZE];
        
        //username_size_size + nonce_size_size + max_username_size + nonce_size
        int MAX_CLIENT_HELLO_SIZE = sizeof(uint8_t) + sizeof(uint8_t) 
					+ MAX_USERNAME_SIZE + CryptographyManager::getNonceSize();

        void createConnection();
        void destroyConnection();
        int getHelloPacket(unsigned char*);
        void obtainUsername();
};
