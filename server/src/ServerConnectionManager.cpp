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
    if(child_pid == 0)
        serveClient(client_socket);

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

	client_nonce_size = deserializer.deserializeInt();
	char* nonce = (char*)calloc(1, client_nonce_size);

	if(nonce == nullptr)
	{
		std::cout << "Error in calloc" << std::endl;
		exit(1);
	}

    // TO DO check username existance
	deserializer.deserializeString(nonce, client_nonce_size);
	client_nonce = nonce;

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
	serializer.serializeInt(sizeof(client_nonce_size));
	serializer.serializeString(nonce, client_nonce_size);
	serializer.serializeInt(sizeof(certificate_size));
	serializer.serializeByteStream(certificate, certificate_size);
	serializer.serializeInt(sizeof(ephemeral_public_key_size));
	serializer.serializeByteStream(ephemeral_public_key, 
													ephemeral_public_key_size);
	serializer.serializeInt(sizeof(signature_size));
	serializer.serializeByteStream(signature, signature_size);														

	return serializer.getOffset();	
}


/* hello packet:
	//  nonce_size   | nonce | certificate_size  | certificate   | 
    //  key_size     | key   | signature_size    | signature     |

*/
void ServerConnectionManager::sendHello()
{

	std::cout << "Starting server sendHello()" << std::endl;

	// get nonce
    nonce = (char*)calloc(1, CryptographyManager::getNonceSize());
    CryptographyManager::getNonce(nonce);

	// get certificate
	FILE* certificate_file = fopen(CERTIFICATE_FILENAME, "r");
	std::cout << CERTIFICATE_FILENAME << std::endl;

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

	std::cout << "reading the certificate" << std::endl;
	int return_value = fread(certificate, 1, 
									certificate_size, certificate_file);

	if(return_value - certificate_size < 0) 
	{ 
		std::cout << "Error in fread" << std::endl;
		exit(1); 
	}

	fclose(certificate_file);

	// TO DO: handle free 

	// std::cout << "Creating the ephemeral private key" << std::endl;
	ephemeral_private_key = CryptographyManager::getPrivateKey();

	// std::cout << "Creating the ephemeral public key" << std::endl;
	ephemeral_public_key = CryptographyManager::getPublicKey(
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

	std::cout << "building the signature" << std::endl;
	signature = CryptographyManager::signMessage(clear_message, 
				signature_size, PRIVATE_KEY_FILENAME, clear_message_size);

	
	unsigned char* hello_packet = (unsigned char*)calloc(1, MAX_HELLO_SIZE);

	if(hello_packet == nullptr)
	{
		std::cout << "Error in calloc" << std::endl;
		exit(1);
	}

	unsigned int hello_packet_size = getHelloPacket(hello_packet);

    sendPacket(hello_packet, hello_packet_size);
	free(hello_packet);
	free(signature);
	free(clear_message);
}

