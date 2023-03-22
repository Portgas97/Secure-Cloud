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

		// will be called on each ServerConnectionManager instance
		void handleHandshake();
		void handleRequest();


    private:
		char* logged_user_username;

		const char* CERTIFICATE_FILENAME = 
									"server/files/pem_files/Certificate.pem";

        const char* PRIVATE_KEY_FILENAME = "server/files/pem_files/Key.pem";

		const char* CLIENT_CERTIFICATE_FILENAME_PREFIX = "server/files/users/";
		const char* CLIENT_CERTIFICATE_FILENAME_SUFFIX = "/Certificate.pem";

		const unsigned int MAX_CLIENT_CERTIFICATE_FILENAME_SIZE = 
									strlen(CLIENT_CERTIFICATE_FILENAME_PREFIX) +
									MAX_USERNAME_SIZE +
									strlen(CLIENT_CERTIFICATE_FILENAME_SUFFIX) + 
									1;

        unsigned char* certificate;
        unsigned int certificate_size;

		EVP_PKEY* deserialized_ephemeral_client_key;

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
                                + sizeof(signature_size)
                                + signature_size;

        void createConnection();
        void destroyConnection();
        void serveClient(int);
		unsigned char* getCertificateFromFile(const char*, unsigned int&);
        void sendHello();
        void receiveHello();
		void receiveFinalMessage();
		void sendFinalMessage();
		void setSharedKey();
        unsigned int getHelloPacket(unsigned char*); 
		void getFilenamesList(Deserializer);
        
};

#endif
