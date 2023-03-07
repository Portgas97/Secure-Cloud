class ConnectionManager
{
    public:
        ConnectionManager();

        void sendPacket(unsigned char*, uint32_t);

        void receivePacket(unsigned char*);

        //closeSocket();

        ~ConnectionManager();

    protected:
        int socket;
        const int SERVER_PORT = 3490;
        const char* SERVER_ADDRESS = "127.0.0.1";
        unsigned char* nonce;

        
        virtual createConnection() = 0;

        virtual destroyConnection() = 0;


};
        