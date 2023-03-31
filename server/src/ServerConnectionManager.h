#ifndef SERVER_CONNECTION_MANAGER_H
#define SERVER_CONNECTION_MANAGER_H
#include "../../common/src/ConnectionManager.h"

class ServerConnectionManager: public ConnectionManager 
{
    public:
        ServerConnectionManager();
		ServerConnectionManager(int);
        ~ServerConnectionManager();

        void acceptRequest();

		// will be called on each ServerConnectionManager instance
		void handleHandshake();
		unsigned int handleRequest();


    private:
		char logged_username[MAX_USERNAME_SIZE];
        unsigned int logged_username_size;

		// paths
		const char* CERTIFICATE_FILENAME = 
									"server/files/pem_files/Certificate.pem";

        const char* PRIVATE_KEY_FILENAME = "server/files/pem_files/Key.pem";

		const char* CLIENT_CERTIFICATE_FILENAME_PREFIX = "server/files/users/";
		const char* CLIENT_CERTIFICATE_FILENAME_SUFFIX = 
												"/pem_files/Certificate.pem";

		const char* CLIENT_STORAGE_DIRECTORY_NAME_PREFIX = 
														"server/files/users/";
		const char* CLIENT_STORAGE_DIRECTORY_NAME_SUFFIX = "/storage/";

		const char* BASE_PATH = "/home/Secure-Cloud/";

		const char* USERS_DIRECTORY = "server/files/users/";		


        unsigned char* certificate;
        unsigned int certificate_size;

		EVP_PKEY* deserialized_ephemeral_client_key;

        
		// max sizes
		const unsigned int MAX_CLIENT_CERTIFICATE_FILENAME_SIZE = 
									strlen(CLIENT_CERTIFICATE_FILENAME_PREFIX) +
									MAX_USERNAME_SIZE +
									strlen(CLIENT_CERTIFICATE_FILENAME_SUFFIX) + 
									1;
        const unsigned int MAX_CONNECTIONS = 10;

        //  nonce_size   | nonce | certificate_size  | certificate   | 
        //  key_size     | key   | signature_size    | signature     |
        
        
        const unsigned int MAX_FILENAME_SIZE = 100;

        void createConnection();
        void destroyConnection();
        void serveClient(int);
        void sendHello();
        void receiveHello();
		void receiveFinalHandshakeMessage();
		void sendAckMessage();
		void setSharedKey();
        void getHelloPacket(unsigned char*); 
		void getFilenamesList(Deserializer);
		void handleListOperation();
		void handleUploadOperation(std::string, std::string, unsigned char*,
									unsigned int);
		void handleDeleteOperation(std::string);
        void handleDownloadOperation(std::string);
		void handleLogoutOperation();
        const char* canonicalizeUserPath(const char*);
		void sendError();
		void handleRenameOperation(const char*, std::string);
		unsigned char* getMessagePlaintext(unsigned char*, unsigned int&);

};

#endif
