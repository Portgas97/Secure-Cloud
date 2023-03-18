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
	ServerConnectionManager request_handler =
 										ServerConnectionManager(client_socket);
	request_handler.handleHandshake();
    
}

void ServerConnectionManager::handleHandshake()
{
	receiveHello();
	sendHello();
	receiveFinalMessage();
	setSharedKey();
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
	unsigned int logged_user_username_size = deserializer.deserializeInt();

	logged_user_username = (char*)calloc(1, logged_user_username_size);

	if(logged_user_username == nullptr)
	{
		std::cout << "Error in calloc" << std::endl;
		exit(1);
	}

	deserializer.deserializeString(logged_user_username, 
									logged_user_username_size);

	unsigned int client_nonce_size = deserializer.deserializeInt();

	if(client_nonce_size != NONCE_SIZE)
	{
		std::cout << "Error in nonce size reception" << std::endl;
		exit(1);
	}

    // TO DO check username existance
	deserializer.deserializeString(client_nonce, client_nonce_size);

	free(hello_packet);

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

	ephemeral_private_key = CryptographyManager::getPrivateKey();
	ephemeral_public_key = CryptographyManager::serializeKey(
							ephemeral_private_key, 
							ephemeral_public_key_size);


	// message: server_public_key | client_nonce
	unsigned int clear_message_size =  ephemeral_public_key_size 
						+ CryptographyManager::getNonceSize();

	unsigned char* clear_message = (unsigned char*) calloc(1, 
														clear_message_size);
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

	unsigned int hello_packet_size = getHelloPacket(hello_packet);

    sendPacket(hello_packet, hello_packet_size);
	free(hello_packet);
	free(signature);
	free(clear_message);

}

void ServerConnectionManager::receiveFinalMessage()
{
	std::cout << "start receivaFinalMessage" << std::endl;
	unsigned char* final_handshake_message = nullptr;
	receivePacket(final_handshake_message);

	Deserializer deserializer = Deserializer(final_handshake_message);

	unsigned int ephemeral_client_key_size = deserializer.deserializeInt();
    unsigned char* ephemeral_client_key = (unsigned char*)calloc(1, 
                                                    ephemeral_client_key_size);
    if(ephemeral_client_key == nullptr)
    {
        std::cout << "Error in calloc" << std::endl;
        exit(1);
    }
    deserializer.deserializeByteStream(ephemeral_client_key, 
                                                    ephemeral_client_key_size);
	deserialized_ephemeral_client_key =
                    CryptographyManager::deserializeKey(ephemeral_client_key,
                                                    ephemeral_client_key_size);

    unsigned int client_signature_size = deserializer.deserializeInt();
    unsigned char* client_signature = (unsigned char*)calloc(1, 
                                                    client_signature_size);
    if(client_signature == nullptr)
    {
        std::cout << "Error in calloc" << std::endl;
        exit(1);
    }
    deserializer.deserializeByteStream(client_signature, 
                                                    client_signature_size);

	std::cout << "client_signature: " << std::endl;
	printBuffer(client_signature, client_signature_size);

	// build the message to check: key | server_nonce
    unsigned int clear_message_size = ephemeral_client_key_size 
                                    + CryptographyManager::getNonceSize();
    unsigned char *clear_message = (unsigned char*)calloc(1, 
                                                    clear_message_size);
	
    if(clear_message == nullptr)
    {
        std::cout << "Error in calloc" << std::endl;
        exit(1);
    }

    memcpy(clear_message, ephemeral_client_key, ephemeral_client_key_size);
    memcpy(clear_message + ephemeral_client_key_size, server_nonce, 
                            CryptographyManager::getNonceSize());

	std::cout << "message that should be signed: " << std::endl;
	printBuffer(clear_message, clear_message_size);

	// read the client public key from file

    // build the client public key filename concatenating the prefix, 
	// the client username and the suffix
    char* client_public_key_filename = (char*)
								calloc(1, MAX_CLIENT_PUBLIC_KEY_FILENAME_SIZE);
	if(client_public_key_filename == nullptr)
	{
		std::cout << "Error in calloc" << std::endl;
		exit(1);
	}

    strcpy(client_public_key_filename, CLIENT_PUBLIC_KEY_FILENAME_PREFIX);
    strcat(client_public_key_filename, logged_user_username);
    strcat(client_public_key_filename, CLIENT_PUBLIC_KEY_FILENAME_SUFFIX);

	std::cout << "filename: " << client_public_key_filename << std::endl;

	FILE* client_public_key_file = fopen(client_public_key_filename, "r");
	if(client_public_key_file == nullptr)
	{
		std::cout << "Error in fopen" << std::endl;
		exit(1);
	}
	EVP_PKEY* client_public_key = PEM_read_PUBKEY(client_public_key_file,
													nullptr,
													nullptr,
													nullptr);

	fclose(client_public_key_file);

    CryptographyManager::verifySignature(client_signature,client_signature_size, 
                                        clear_message, clear_message_size, 
                                        client_public_key);

	free(client_public_key);	
	std::cout << "end receiveFinalMessage" << std::endl;
}

void ServerConnectionManager::setSharedKey()
{
	// derive shared secret that will be used to derive the session key
	size_t shared_secret_size;
	unsigned char* shared_secret = CryptographyManager::getSharedSecret
											(ephemeral_private_key,
											deserialized_ephemeral_client_key,
											&shared_secret_size);
	// derive session key
	shared_key = CryptographyManager::getSharedKey(shared_secret, 
													shared_secret_size);

}
