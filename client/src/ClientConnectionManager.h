#ifndef CLIENT_CONNECTION_MANAGER_H
#define CLIENT_CONNECTION_MANAGER_H
#include "../../common/src/ConnectionManager.h"

class ClientConnectionManager: public ConnectionManager
{
    public:
        ClientConnectionManager();
		void handleHandshake();	
        void retrieveCommand();


    private:
		// paths
        const char* PRIVATE_KEY_FILENAME_SUFFIX = "/pem_files/Key.pem";
        const char* PRIVATE_KEY_FILENAME_PREFIX = "client/files/";

		const char* STORAGE_DIRECTORY_NAME_PREFIX = "client/files/";
		const char* STORAGE_DIRECTORY_NAME_SUFFIX = "/storage/";

		const char* USERS_DIRECTORY = "server/files/users/";				
        
        char username[MAX_USERNAME_SIZE];
		EVP_PKEY* deserialized_ephemeral_server_key;
        
		// max sizes
        const unsigned int MAX_PRIVATE_KEY_FILENAME_SIZE = 
                                strlen(PRIVATE_KEY_FILENAME_PREFIX) + 
                                MAX_USERNAME_SIZE +
                                strlen(PRIVATE_KEY_FILENAME_SUFFIX) + 1;     
        

        void createConnection();
        void destroyConnection();
        void obtainUsername();
        void sendHello();
        void receiveHello();
		void sendFinalHandshakeMessage();
		void receiveAckMessage();
		void setSharedKey();	
        void getHelloPacket(unsigned char*);
        unsigned int getFinalMessage(unsigned char*);

        void showMenu();
        void uploadFile(std::string);
        void downloadFile(std::string);
        void deleteFile(std::string);
        void printFilenamesList();
        void renameFile(std::string, std::string);
        void logout();

};

#endif
