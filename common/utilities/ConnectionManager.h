class ConnectionManager
{
    public:
        ConnectionManager();

        //sendPacket();

        void receivePacket(int, char*);

        //closeSocket();

        ~ConnectionManager();

    protected:
        int socket;
        const int SERVER_PORT = 3490;
        const char* SERVER_ADDRESS = "127.0.0.1";

        
        virtual createConnection() = 0;

        virtual destroyConnection() = 0;


};
        