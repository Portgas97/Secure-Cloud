#ifndef SERVER_CONNECTION_MANAGER_H
#define SERVER_CONNECTION_MANAGER_H
#include "../../common/utilities/ConnectionManager.h"

class ServerConnectionManager: public ConnectionManager 
{
    public:
        ServerConnectionManager();
		ServerConnectionManager(int);
        ~ServerConnectionManager();

        void acceptRequest();


    private:
		char* logged_user_username;

		const char* CERTIFICATE_FILENAME = "server/files/Server_cert.pem";
        const char* PRIVATE_KEY_FILENAME = "server/files/Server_key.pem";
		const char* CLIENT_PUBLIC_KEY_FILENAME_PREFIX = "server/files/";
		const char* CLIENT_PUBLIC_KEY_FILENAME_SUFFIX = "_key.pem";

		// TO DO: change this constant
		const unsigned int MAX_CLIENT_PUBLIC_KEY_FILENAME_SIZE = 2048;

        unsigned char* certificate;
        unsigned long int certificate_size;

		EVP_PKEY* ephemeral_private_key;

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
		void receiveFinalHandshakeMessage();
        unsigned int getHelloPacket(unsigned char*);       
        
};

#endif
