#include "ServerConnectionManager.h"
#include <stdio.h>

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
		std::cout << "Error in socket" << std::endl;
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
        std::cout << "Error in bind" << std::endl;
        exit(1);
    }

    if((listen(socket_fd, MAX_CONNECTIONS)) < 0)
    {
        std::cout << "Error in listen" << std::endl;
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
        std::cout << "Error in accept" << std::endl;
        exit(1);
    }

    // create the child who will serve the client                        
    pid_t child_pid = fork();

    if(child_pid < 0) 
    {
        std::cout << "Error in fork"; << std::endl
        exit(1);
    }

    // the child will enter in the if block
    if(child_pid == 0)
        serveClient(client_socket);

}


void ServerConnectionManager::serveClient(int client_socket)
{
	ServerConnectionManager requestHandler =
 										ServerConnectionManager(client_socket);
    requestHandler.receiveHello();
}


/*
    it receives and parses client hello packet and sends back server 
	hello packet
*/
void ServerConnectionManager::receiveHello()
{
	unsigned char* hello_packet = nullptr;
	receivePacket(hello_packet);

	Deserializer deserializer = Deserializer(hello_packet);

	// received_packet: username_size | username | nonce_size | nonce
	int username_size = deserializer.deserializeInt();

	char* username = (char*)calloc(1, username_size);

	if(username == nullptr)
	{
		std::cout << "Error in calloc" << std::endl;
		exit(1);
	}

	deserializer.deserializeString(username, username_size);

	int nonce_size = deserializer.deserializeInt();
	char* nonce = (char*)calloc(1, nonce_size);

	if(nonce == nullptr)
	{
		std::cout << "Error in calloc" << std::endl;
		exit(1);
	}

    // TO DO check username existance

}

void ServerConnectionManager::sendHello()
{
    // nonce_size | nonce | certificate_size | certificate | key_size | key
    // signature_size | signature

	// get nonce
    nonce = (char*)calloc(1, CryptographyManager::getNonceSize());
    CryptographyManager::getNonce(nonce);

	// get certificate
	FILE* server_certificate_file = fopen(SERVER_CERTIFICATE_FILENAME, "rb");
	if(server_certificate_file == nullptr)
	{
		std::cout << "Error in fopen" << std::endl;
		exit(1);
	}

	// get file size

	// move the file pointer to the end of the file
	fseek(server_certificate_file, 0, SEEK_END);

	// returns the file pointer position
	unsigned long int server_certificate_file_size = 
												ftell(server_certificate_file);
	
	// move file pointer to the beginning of the file
	fseek(server_certificate_file, 0, SEEK_SET);
	
	unsigned char* server_certificate = (unsigned char*)
										calloc(1, server_certificate_file_size);

	if(server_certificate == nullptr) 
	{ 
		std::cout << "Error in calloc" << std::endl; 
		exit(1); 
	}

	int return_value = fread(server_certificate, 1, 
						server_certificate_file_size, server_certificate_file);
	
	if(return_value < server_certificate_file_size) 
	{
		std::cout << "Error in fread" << std::endl;
		exit(1);
	}

	fclose(server_certificate_file);

	// get private key
	EVP_PKEY* private_key = CryptographyManager::getPrivateKey();

	
}




