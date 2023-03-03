#include "ConnectionManager.h"
#include <string>

class ServerConnectionManager: public ConnectionManager 
{
    public:
        ServerConnectionManager();

    private:
        const int MAX_CONNECTIONS = 10;
        const int SERVER_PORT = 3490;
        const string SERVER_ADDRESS = "127.0.0.1";
        int socket;
        void createConnection();
        
}