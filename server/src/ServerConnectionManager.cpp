#include "ServerConnectionManager.h"
#include <stdio.h>

ServerConnectionManager::ServerConnectionManager()
{
    createConnection();
}

ServerConnectionManager::~ServerConnectionManager()
{

}

ServerConnectionManager::ServerConnectionManager(int socket)
{
	socket_fd = socket;
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

    struct sockaddr_in address;
    std::memset(&address, 0, sizeof(address));

    // set the parameters for address
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(SERVER_PORT); 

    if((bind(socket_fd, (struct sockaddr *) &address, 
						sizeof(address))) < 0)
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
        std::cout << "Error in fork" << std::endl;
        exit(1);
    }

    // the child will enter in the if block
    if(child_pid == 0){
		std::cout << "Connection accepted, serving client..." << std::endl;
        serveClient(client_socket);
		std::cout << "Client served" << std::endl;
	}

}


void ServerConnectionManager::serveClient(int client_socket)
{
	ServerConnectionManager requestHandler =
 										ServerConnectionManager(client_socket);

    requestHandler.receiveHello();
	requestHandler.sendHello();
}


/*
    it receives and parses client hello packet and sends back server 
	hello packet
*/
void ServerConnectionManager::receiveHello()
{
	std::cout << "receiveHello() init" << std::endl;
	unsigned char* hello_packet = nullptr;
	receivePacket(hello_packet);

	Deserializer deserializer = Deserializer(hello_packet);
		
	// received_packet: username_size | username | nonce_size | nonce
	unsigned int username_size = deserializer.deserializeInt();

	char* username = (char*)calloc(1, username_size);

	if(username == nullptr)
	{
		std::cout << "Error in calloc" << std::endl;
		exit(1);
	}

	deserializer.deserializeString(username, username_size);
	std::cout << "received username: " << username << std::endl;

	unsigned int client_nonce_size = deserializer.deserializeInt();

	if(client_nonce_size != NONCE_SIZE)
	{
		std::cout << "client_nonce_size: " << client_nonce_size << ", NONCE_SIZE: " << NONCE_SIZE << std::endl;
		std::cout << "Error in nonce size reception" << std::endl;
		exit(1);
	}
	// char* received_nonce = (char*)calloc(1, client_nonce_size);

	// if(received_nonce == nullptr)
	// {
	// 	std::cout << "Error in calloc" << std::endl;
	// 	exit(1);
	// }

    // TO DO check username existance
	deserializer.deserializeString(client_nonce, client_nonce_size);

	free(hello_packet);
	std::cout << "receiveHello() end" << std::endl;

}


/*
    it creates the hello packet and returns it.
    It returns the hello packet size
*/
unsigned int ServerConnectionManager::getHelloPacket(unsigned char* hello_packet)
{
	Serializer serializer = Serializer(hello_packet);

    // nonce_size | nonce | certificate_size | certificate | key_size | key
    // signature_size | signature
	serializer.serializeInt(NONCE_SIZE);
	serializer.serializeString(server_nonce, NONCE_SIZE);
	serializer.serializeInt(certificate_size);
	serializer.serializeByteStream(certificate, certificate_size);
	serializer.serializeInt(ephemeral_public_key_size);
	serializer.serializeByteStream(ephemeral_public_key, 
													ephemeral_public_key_size);
	serializer.serializeInt(signature_size);
	serializer.serializeByteStream(signature, signature_size);														

	return serializer.getOffset();	
}


/* hello packet:
	//  nonce_size   | nonce | certificate_size  | certificate   | 
    //  key_size     | key   | signature_size    | signature     |

*/
void ServerConnectionManager::sendHello()
{

	std::cout << "sendHello() init" << std::endl;
	// get nonce
    CryptographyManager::getNonce(server_nonce);

	// get certificate
	FILE* certificate_file = fopen(CERTIFICATE_FILENAME, "r");

	if(certificate_file == nullptr)
	{
		perror("Error in fopen\n");
		exit(1);
	}

	// get file size
	// move the file pointer to the end of the file
	fseek(certificate_file, 0, SEEK_END);
	// returns the file pointer position
	certificate_size = ftell(certificate_file);
	// move file pointer to the beginning of the file
	fseek(certificate_file, 0, SEEK_SET);
	
	
	certificate = (unsigned char*) calloc(1, certificate_size);

	if(certificate == nullptr) 
	{ 
		std::cout << "Error in calloc" << std::endl; 
		exit(1); 
	}

	unsigned int return_value = fread(certificate, 1, 
									certificate_size, certificate_file);

	if(return_value < certificate_size) 
	{ 
		std::cout << "Error in fread" << std::endl;
		exit(1); 
	}

	fclose(certificate_file);

	// TO DO: handle free 

	ephemeral_private_key = CryptographyManager::getPrivateKey();

	ephemeral_public_key = CryptographyManager::serializeKey(
							ephemeral_private_key, 
							ephemeral_public_key_size);


	// message: server_public_key | client_nonce
	unsigned int clear_message_size =  ephemeral_public_key_size 
						+ CryptographyManager::getNonceSize();

	unsigned char* clear_message = (unsigned char*) calloc(1, clear_message_size);
	if(clear_message == nullptr)
	{
		std::cout << "Error in calloc" << std::endl;
		exit(1);
	}

	// building the message to be signed 
	memcpy(clear_message, ephemeral_public_key, ephemeral_public_key_size);
	memcpy(clear_message + ephemeral_public_key_size, &client_nonce, 
				CryptographyManager::getNonceSize());

	signature = CryptographyManager::signMessage(clear_message, 
				clear_message_size, PRIVATE_KEY_FILENAME, signature_size);
	
	unsigned char* hello_packet = (unsigned char*)calloc(1, MAX_HELLO_SIZE);

	if(hello_packet == nullptr)
	{
		std::cout << "Error in calloc" << std::endl;
		exit(1);
	}

	std::cout << "call to getHelloPacket()" << std::endl;
	unsigned int hello_packet_size = getHelloPacket(hello_packet);

    sendPacket(hello_packet, hello_packet_size);
	free(hello_packet);
	free(signature);
	free(clear_message);
	std::cout << "sendHello() end" << std::endl;

}

