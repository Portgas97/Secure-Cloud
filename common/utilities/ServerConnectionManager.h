#include "ConnectionManager.h"

class ServerConnectionManager: public ConnectionManager 
{
    public:
        ServerConnectionManager();
        void acceptRequest();

    private:
        const int MAX_CONNECTIONS = 10;
        void createConnection();
        void destroyConnection();
        void serveClient(int);
        void receiveHello(int);
        
};
