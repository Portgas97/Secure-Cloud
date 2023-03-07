#include "ConnectionManager.h"
#include "CryptoManager.h"

class ClientConnectionManager: public ConnectionManager
{
    public:
        ClientConnectionManager();

        void sendHello();

        // connect();

    private:
        int MAX_USERNAME_SIZE = 50;
        char username[MAX_USERNAME_SIZE];
        
        //username_size_size + nonce_size_size + max_username_size + nonce_size
        int MAX_CLIENT_HELLO_SIZE = sizeof(uint8_t) + sizeof(uint8_t) + MAX_USERNAME_SIZE + CryptoManager.getNonceSize();

        unsigned char* getHelloPacket();

        void obtainUsername();
};