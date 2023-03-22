#ifndef CLIENT_CONNECTION_MANAGER_H
#define CLIENT_CONNECTION_MANAGER_H
#include "../../common/utilities/ConnectionManager.h"

class ClientConnectionManager: public ConnectionManager
{
    public:
        ClientConnectionManager();
        ~ClientConnectionManager();
		void handleHandshake();	
        void retrieveCommand();


    private:
        const char* PRIVATE_KEY_FILENAME_SUFFIX = "/pem_files/Key.pem";
        const char* PRIVATE_KEY_FILENAME_PREFIX = "client/files/";
        
        char username[MAX_USERNAME_SIZE];
		EVP_PKEY* deserialized_ephemeral_server_key;
        
        const unsigned int MAX_PRIVATE_KEY_FILENAME_SIZE = 
                                strlen(PRIVATE_KEY_FILENAME_PREFIX) + 
                                MAX_USERNAME_SIZE +
                                strlen(PRIVATE_KEY_FILENAME_SUFFIX) + 1;

        const unsigned int MAX_FINAL_HANDSHAKE_MESSAGE_SIZE =                                 
                                sizeof(ephemeral_public_key_size)
                                + ephemeral_public_key_size
                                + sizeof(signature_size)
                                + signature_size;
        
        const unsigned int MAX_HELLO_SIZE = 
                    sizeof(MAX_USERNAME_SIZE) 
                    + MAX_USERNAME_SIZE 
                    + sizeof(CryptographyManager::getNonceSize()) 
                    + CryptographyManager::getNonceSize();

        void createConnection();
        void destroyConnection();
        void obtainUsername();
        void sendHello();
        void receiveHello();
		void sendFinalMessage();
		void receiveFinalMessage();
		void setSharedKey();	
        unsigned int getHelloPacket(unsigned char*);
        unsigned int getFinalMessage(unsigned char*);

        void showMenu();
        void uploadFile();
        void downloadFile();
        void deleteFile();
        void printFilenamesList();
        void renameFile();
        void logout();

};

#endif
