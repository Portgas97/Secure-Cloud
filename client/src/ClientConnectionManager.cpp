
#include "ClientConnectionManager.h"

ClientConnectionManager::ClientConnectionManager()
{
    createConnection();
    obtainUsername();
}

ClientConnectionManager::~ClientConnectionManager()
{

}


/*
    it initializes the connection socket and performs the actual connection
*/
void ClientConnectionManager::createConnection()
{
    socket_fd = socket(AF_INET, SOCK_STREAM, 0);

    if(socket_fd < 0)
    {
        std::cout << "Error in socket" << std::endl;
        exit(1);
    }

    const int yes = 1;
    setsockopt(socket_fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int));

    struct sockaddr_in server_address;

    std::memset(&server_address, 0, sizeof(server_address));
    server_address.sin_family = AF_INET;
    server_address.sin_port = htons(SERVER_PORT);
    inet_pton(AF_INET, SERVER_ADDRESS, &server_address.sin_addr);

    socklen_t address_length = (socklen_t) sizeof(server_address);
    int return_value = connect(socket_fd, (struct sockaddr*)&server_address, 
																address_length);

    if(return_value < 0)
    {
        std::cout << "Error in connect" << std::endl;
        exit(1);
    }

}


void ClientConnectionManager::destroyConnection()
{
    // TO DO
}


/*
    it asks the username to the user and assigns it to the relative 
    class attribute
*/
void ClientConnectionManager::obtainUsername()
{
    std::cout << "Insert your username: ";

    // get the input username from the client
    if(fgets(username, MAX_USERNAME_SIZE, stdin) == nullptr)
    {
        std::cout << "Error in fgets" << std::endl;
        exit(1);
    }

    // check if username is too long
    if(!strchr(username, '\n'))
    {
        std::cout << "Error: the username you inserted is too long" << std::endl;
        exit(1);
    }

    username[strcspn(username, "\n")] = 0;

}

/*
    it creates the client nonce, the client hello and sends the client
    hello to the server
*/
void ClientConnectionManager::sendHello()
{
	nonce = (char*)calloc(1, CryptographyManager::getNonceSize());
    if(nonce == nullptr)
    {
        std::cout << "Error in calloc" << std::endl;
        exit(1);
    }

    CryptographyManager::getNonce(nonce);

    // hello_packet: username_size | username | nonce_size | nonce
    unsigned char* hello_packet = (unsigned char *) calloc(1, 
														MAX_CLIENT_HELLO_SIZE);

    if (hello_packet == nullptr) 
    {
        std::cout << "Error in hello packet calloc" << std::endl;
        exit(1);
    }

    int hello_packet_size = getHelloPacket(hello_packet);

    sendPacket(hello_packet, hello_packet_size);
	free(hello_packet);
}


void ClientConnectionManager::receiveHello()
{

}

/*
    it creates the hello packet and returns it.
    It returns the hello packet size
*/
int ClientConnectionManager::getHelloPacket(unsigned char* hello_packet)
{
	Serializer serializer = Serializer(hello_packet);

    // hello_packet: username_size | username | nonce_size | nonce
	serializer.serializeInt(strlen(username) + 1);
	serializer.serializeString(username, strlen(username) + 1);
	serializer.serializeInt(sizeof(nonce));
	serializer.serializeString(nonce, sizeof(nonce));

	return serializer.getOffset();	
}
