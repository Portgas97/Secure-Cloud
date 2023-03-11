#include "ServerConnectionManager.h"

ServerConnectionManager::ServerConnectionManager()
{
    createConnection();
}

ServerConnectionManager::~ServerConnectionManager()
{

}

ServerConnectionManager::ServerConnectionManager(int socket_fd)
{
	this->socket_fd = socket_fd;
}

void ServerConnectionManager::createConnection()
{
    socket_fd = socket(AF_INET, SOCK_STREAM, 0);

	if(socket_fd < 0)
	{
		std::cout << "Error in socket\n";
		exit(1);
	}

    const int yes = 1;
    setsockopt(socket_fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int));

    struct sockaddr_in server_address;
    std::memset(&server_address, 0, sizeof(server_address));

    // set the parameters for server_address
    server_address.sin_family = AF_INET;
    server_address.sin_addr.s_addr = INADDR_ANY;
    server_address.sin_port = htons(SERVER_PORT); 

    if((bind(socket_fd, (struct sockaddr *) &server_address, 
						sizeof(server_address))) < 0)
    {
        std::cout << "Error in bind\n";
        exit(1);
    }

    if((listen(socket_fd, MAX_CONNECTIONS)) < 0)
    {
        std::cout << "Error in listen\n";
        exit(1);
    }

}


void ServerConnectionManager::destroyConnection()
{

}


void ServerConnectionManager::acceptRequest()
{
    int client_socket;

    // clear the client_address structure
    struct sockaddr_in client_address;
    std::memset((void*) &client_address, 0, sizeof(client_address));

    // address length
    socklen_t addr_size;
    addr_size = sizeof(struct sockaddr_in);

    // create the new socket for the connection with a client
    if((client_socket = accept(socket_fd, (struct sockaddr *) &client_address, 
							&addr_size)) < 0)
    {
        std::cout << "Error in accept\n";
        exit(1);
    }

    // create the child who will serve the client                        
    pid_t child_pid = fork();

    if(child_pid < 0) 
    {
        std::cout << "Error in fork\n";
        exit(1);
    }

    // the child will enter in the if block
    if(child_pid == 0)
        serveClient(client_socket);

}

/*
    it receives and parses client hello packet and sends back server 
	hello packet
*/
void ServerConnectionManager::receiveHello()
{
	unsigned char* hello_packet = nullptr;
	receivePacket(hello_packet);

	//std::cout << "hello_packet: " << hello_packet << "\n";
	/*std::cout << "hello_packet: ";
	std::cout << hello_packet[0];
	std::cout << '\n';
*/

	Deserializer deserializer = Deserializer(hello_packet);

	// received_packet: username_size | username | nonce_size | nonce
	int username_size = deserializer.deserializeInt();
	std::cout << "username_size " << username_size << "\n";

	char* username = (char*)calloc(1, username_size);

	if(username == nullptr)
	{
		std::cout << "Error in calloc\n";
		exit(1);
	}

	deserializer.deserializeString(username, username_size);
	std::cout << "username " << username << "\n";	

	int nonce_size = deserializer.deserializeInt();
	std::cout << "nonce_size " << nonce_size << "\n";
	char* nonce = (char*)calloc(1, nonce_size);
	std::cout << "nonce" << nonce << "\n";

	if(nonce == nullptr)
	{
		std::cout << "Error in calloc\n";
		exit(1);
	}


/*    // received_packet: username_size | username | nonce_size | nonce
    unsigned char* received_packet = nullptr;
    receivePacket(received_packet);

    uint32_t username_size;
    
    // retrieve the client username size
    memcpy(&username_size, received_packet, sizeof(username_size));
    username_size = ntohl(username_size);

    // it points to the right packet offset
    int packet_offset = sizeof(username_size);

    char* username = nullptr;
    // retrieve the client username
    memcpy(username, received_packet + packet_offset, username_size);

    std::cout << "Received hello packet from user " << username << "\n";

    packet_offset += username_size;

    uint32_t client_nonce_size;

    // retrieve the nonce size
    memcpy(&client_nonce_size, received_packet + packet_offset, sizeof(client_nonce_size));

    packet_offset += sizeof(client_nonce_size);

    char* client_nonce = nullptr;

    // retrieve the nonce
    memcpy(client_nonce, received_packet + packet_offset, client_nonce_size);
*/
}


void ServerConnectionManager::serveClient(int client_socket)
{
	ServerConnectionManager requestHandler =
 										ServerConnectionManager(client_socket);
    requestHandler.receiveHello();
}
