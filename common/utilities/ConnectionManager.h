class ConnectionManager
{
    public:
        ConnectionManager();

        //sendPacket();

        //receivePacket();

        //closeSocket();

        ~ConnectionManager();

    private:

        virtual createConnection() = 0;

        virtual destroyConnection() = 0;


};
        