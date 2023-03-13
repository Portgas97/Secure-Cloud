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

        void sendHello();
        void receiveHello();

    private:
		const char* SERVER_CERTIFICATE_FILENAME = 
											"../common/files/Server_cert.pem";
        const int MAX_CONNECTIONS = 10;
        void createConnection();
        void destroyConnection();
        void serveClient(int);
        
};

#endif
