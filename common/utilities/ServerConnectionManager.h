#include "ConnectionManager.h"

class ServerConnectionManager: public ConnectionManager 
{
    public:
        ServerConnectionManager();
        void accept();

    private:
        const int MAX_CONNECTIONS = 10;
        void createConnection();
        void serveClient(int);
        
}