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
		std::cout << "Error in socket\n";
		exit(1);
	}

    const int yes = 1;
    setsockopt(socket_fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int));

    struct sockaddr_in address;
    std::memset(&address, 0, sizeof(address));

    // set the parameters for address
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(SERVER_PORT); 

    if((bind(socket_fd, (struct sockaddr *) &address, 
						sizeof(address))) < 0)
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


void ServerConnectionManager::serveClient(int client_socket)
{
	ServerConnectionManager requestHandler =
 										ServerConnectionManager(client_socket);
    char* client_nonce = requestHandler.receiveHello();
	sendHello(client_nonce);
}


/*
    it receives and parses client hello packet and sends back server 
	hello packet
*/
char* ServerConnectionManager::receiveHello()
{
	unsigned char* hello_packet = nullptr;
	receivePacket(hello_packet);

	Deserializer deserializer = Deserializer(hello_packet);

	// received_packet: username_size | username | nonce_size | nonce
	int username_size = deserializer.deserializeInt();

	char* username = (char*)calloc(1, username_size);

	if(username == nullptr)
	{
		std::cout << "Error in calloc\n";
		exit(1);
	}

	deserializer.deserializeString(username, username_size);

	int nonce_size = deserializer.deserializeInt();
	char* nonce = (char*)calloc(1, nonce_size);

	if(nonce == nullptr)
	{
		std::cout << "Error in calloc\n";
		exit(1);
	}

    // TO DO check username existance

	return nonce;
}

/* hello packet:
	nonce_size | nonce | certificate_size | certificate | key_size | key
  	signature_size | signature

*/
void ServerConnectionManager::sendHello(char* client_nonce)
{

	// get nonce
    nonce = (char*)calloc(1, CryptographyManager::getNonceSize());
    CryptographyManager::getNonce(nonce);

	// get certificate
	FILE* certificate_file = fopen(CERTIFICATE_FILENAME, "rb");
	if(certificate_file == nullptr)
	{
		std::cout << "Error in fopen\n";
		exit(1);
	}

	// get file size

	// move the file pointer to the end of the file
	fseek(certificate_file, 0, SEEK_END);

	// returns the file pointer position
	unsigned long int certificate_file_size = ftell(certificate_file);
	
	// move file pointer to the beginning of the file
	fseek(certificate_file, 0, SEEK_SET);
	
	certificate = (unsigned char*) calloc(1, certificate_file_size);

	if(certificate == nullptr) 
	{ 
		std::cout << "Error in calloc" << std::endl; 
		exit(1); 
	}

	int return_value = fread(certificate, 1, 
									certificate_file_size, certificate_file);

	if(return_value < certificate_file_size) 
	{ 
		std::cout << "Error in fread" << std::endl;
		exit(1); 
	}

	fclose(certificate_file_size);

	// TO DO: handle free 

	ephemeral_private_key = CryptographyManager::getPrivateKey();

	ephemeral_public_key = CryptographyManager::getPublicKey(ephemeral_private_key, ephemeral_public_key_size);

	// message: server_public_key | client_nonce
	int message_size = ephemeral_public_key_size + sizeof(client_nonce);

	unsigned char* message = (unsigned char*) calloc(1, message_size);
	if(message == nullptr)
	{
		std::cout << "Error in calloc" << std::endl;
		exit(1);
	}

	// message creation
	memcpy(message, ephemeral_private_key, ephemeral_public_key_size);

	uint16_t client_nonce_size = sizeof(client_nonce);
	memcpy(message + ephemeral_public_key_size, client_nonce, client_nonce_size);

	unsigned int signed_message_size;
	// message signature
	unsigned char* signed_message = CryptographyManager::signMessage(message, 
				message_size, PRIVATE_KEY_FILENAME, signed_message_size);

	unsigned char* hello_packet = (unsigned char*)calloc(1, MAX_HELLO_SIZE);

	if(hello_packet == nullptr)
	{
		std::cout << "Error in calloc" << std::endl;
		exit(1);
	}

	unsigned int hello_packet_size = getHelloPacket(hello_packet);

    sendPacket(hello_packet, hello_packet_size);
	free(hello_packet);
	free(signed_message);
	free(message);
}

/*
    it creates the hello packet and returns it.
    It returns the hello packet size
*/
int ServerConnectionManager::getHelloPacket(unsigned char* hello_packet)
{
	Serializer serializer = Serializer(hello_packet);

    // nonce_size | nonce | certificate_size | certificate | key_size | key
    // signature_size | signature
	serializer.serializeInt(sizeof(nonce));
	serializer.serializeString(nonce, sizeof(nonce));
	serializer.serializeInt(sizeof(certificate));
	serializer.serializeByteStream(certificate, sizeof(certificate));
	serializer.serializeInt(ephemeral_public_key_size);
	serializer.serializeByteStream(ephemeral_public_key, 
													ephemeral_public_key_size);
	serializer.serializeInt(signed_message_size);
	serializer.serializeByteStream(signed_message, signed_message_size);														

	return serializer.getOffset();	
}
