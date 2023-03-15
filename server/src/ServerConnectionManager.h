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

        // TO DO remove this comment, client_nonce is needed to not have e.g. receiveHello(client_nonce)
        // it is not possible to have different signatures in overridden functions
        char* client_nonce; 
        unsigned char* certificate;
        unsigned long int certificate_size;
        EVP_PKEY* ephemeral_private_key;
        unsigned char* ephemeral_public_key;
        unsigned int ephemeral_public_key_size;
        unsigned char* signature;
        unsigned int signature_size;


        //  nonce_size   | nonce | certificate_size  | certificate   | 
        //  key_size     | key   | signature_size    | signature     |
        
        const unsigned int MAX_CONNECTIONS = 10;
        const unsigned int MAX_HELLO_SIZE = 
                                sizeof(CryptographyManager::getNonceSize())
                                + CryptographyManager::getNonceSize()
                                + sizeof(certificate_size)
                                + certificate_size
                                + sizeof(ephemeral_public_key_size)
                                + ephemeral_public_key_size
                                + sizeof(signature)
                                + signature_size;

        void createConnection();
        void destroyConnection();
        void serveClient(int);
        void sendHello();
        void receiveHello();
        unsigned int getHelloPacket(unsigned char*);        
        
};

#endif
