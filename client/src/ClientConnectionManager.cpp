#include "ClientConnectionManager.h"


ClientConnectionManager::ClientConnectionManager()
{
    createConnection();
    obtainUsername();
}


ClientConnectionManager::~ClientConnectionManager()
{
    // TO DO what to free? shared_key leads to a double-free attempt
}


/*
    it initializes the connection socket and performs the actual connection
*/
void ClientConnectionManager::createConnection()
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
    server_address.sin_family = AF_INET;
    server_address.sin_port = htons(SERVER_PORT);
    inet_pton(AF_INET, SERVER_ADDRESS, &server_address.sin_addr);

    socklen_t address_length = (socklen_t) sizeof(server_address);
    int return_value = connect(socket_fd, (struct sockaddr*)&server_address, 
																address_length);

    if(return_value < 0)
    {
        std::cout << "Error in connect\n";
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
        std::cout << "Error in fgets\n";
        exit(1);
    }

    // check if username is too long
    if(!strchr(username, '\n'))
    {
        std::cout << "Error: the username you inserted is too long\n";
        exit(1);
    }

    username[strcspn(username, "\n")] = 0;
}

/*
	handshake:
	1) client sends client_hello
	2) server receives client_hello and reply with server_hello
	3) client receives server_hello, performs some checks and reply with a final
		handshake message
	4) server receives client final handshake message and performs a check
	5) handshake completed, client and server obtained the shared key
*/
void ClientConnectionManager::handleHandshake()
{
    sendHello();
    receiveHello();
	sendFinalMessage();
	setSharedKey();
	receiveFinalMessage();
}


/*
    it creates the hello packet and returns it.
    It returns the hello packet size
*/
unsigned int ClientConnectionManager::getHelloPacket
												(unsigned char* hello_packet)
{
	Serializer serializer = Serializer(hello_packet);

    // hello_packet: username_size | username | nonce_size | nonce
	serializer.serializeInt(strlen(username) + 1);
 	serializer.serializeString(username, strlen(username) + 1);
	serializer.serializeInt(CryptographyManager::getNonceSize());
	serializer.serializeByteStream(client_nonce, 
                                        CryptographyManager::getNonceSize());

	return serializer.getOffset();	
}


/*
    it creates the client nonce, the client hello and sends the client
    hello to the server
*/
void ClientConnectionManager::sendHello()
{
	client_nonce = (unsigned char*) calloc(1, 
							CryptographyManager::getNonceSize());

	if(client_nonce == nullptr)
	{
		std::cout << "Error in calloc" << std::endl;
		exit(1);
	}

    CryptographyManager::getRandomBytes(client_nonce,
							CryptographyManager::getNonceSize());

    // hello_packet: username_size | username | nonce_size | nonce
    unsigned char* hello_packet = (unsigned char*)calloc(1, MAX_HELLO_SIZE);

    if (hello_packet == nullptr) 
    {
        std::cout << "Error in hello packet calloc\n";
        exit(1);
    }

    unsigned int hello_packet_size = getHelloPacket(hello_packet);

    sendPacket(hello_packet, hello_packet_size);

	free(hello_packet);
}

void ClientConnectionManager::receiveHello()
{
    unsigned char* hello_packet = nullptr;
	receivePacket(hello_packet);

    Deserializer deserializer = Deserializer(hello_packet);

    unsigned int server_nonce_size = deserializer.deserializeInt();

    if(server_nonce_size != CryptographyManager::getNonceSize())
    {
        std::cout << "Error: received nonce size is wrong" << std::endl;
        exit(1);
    }
	server_nonce = (unsigned char*) calloc(1, server_nonce_size);

	if(server_nonce == nullptr)
	{
		std::cout << "Error in calloc" << std::endl;
		exit(1);
	}

    deserializer.deserializeByteStream(server_nonce, server_nonce_size);

    unsigned int server_certificate_size = deserializer.deserializeInt();
    unsigned char* server_certificate = (unsigned char*)calloc(1, 
                                                    server_certificate_size);
    if(server_certificate == nullptr)
    {
        std::cout << "Error in calloc" << std::endl;
        exit(1);
    }

    deserializer.deserializeByteStream(server_certificate, 
                                                    server_certificate_size);

    X509* deserialized_server_certificate = 
                        CryptographyManager::deserializeCertificate
								(server_certificate, server_certificate_size);

    CryptographyManager cryptography_manager = CryptographyManager();
    cryptography_manager.verifyCertificate(deserialized_server_certificate);                                                        

    EVP_PKEY* server_public_key =
                         X509_get_pubkey(deserialized_server_certificate);

    unsigned int ephemeral_server_key_size = deserializer.deserializeInt();
    unsigned char* ephemeral_server_key = (unsigned char*)calloc(1, 
                                                    ephemeral_server_key_size);
    if(ephemeral_server_key == nullptr)
    {
        std::cout << "Error in calloc" << std::endl;
        exit(1);
    }
    deserializer.deserializeByteStream(ephemeral_server_key, 
                                                    ephemeral_server_key_size);
    
	deserialized_ephemeral_server_key =
                    CryptographyManager::deserializeKey(ephemeral_server_key,
                                                    ephemeral_server_key_size);

    unsigned int server_signature_size = deserializer.deserializeInt();
    unsigned char* server_signature = (unsigned char*)calloc(1, 
                                                    server_signature_size);
    if(server_signature == nullptr)
    {
        std::cout << "Error in calloc" << std::endl;
        exit(1);
    }
    deserializer.deserializeByteStream(server_signature, 
                                                    server_signature_size);

	// build clear_message: server_key | client_nonce
    unsigned int clear_message_size = ephemeral_server_key_size 
                                    + CryptographyManager::getNonceSize();
    unsigned char *clear_message = (unsigned char*)calloc(1, 
                                                    clear_message_size);
    if(clear_message == nullptr)
    {
        std::cout << "Error in calloc" << std::endl;
        exit(1);
    }

    memcpy(clear_message, ephemeral_server_key, ephemeral_server_key_size);
    memcpy(clear_message + ephemeral_server_key_size, client_nonce, 
                            CryptographyManager::getNonceSize());
        
    CryptographyManager::verifySignature(server_signature, 
										server_signature_size, clear_message, 
										clear_message_size, server_public_key);

    free(server_certificate);
	free(ephemeral_server_key);
	free(server_signature);
	free(clear_message);
    free(hello_packet);
}

void ClientConnectionManager::sendFinalMessage()
{
    ephemeral_private_key = CryptographyManager::getPrivateKey();

	ephemeral_public_key = CryptographyManager::serializeKey
												(ephemeral_private_key,
                                                ephemeral_public_key_size);

    // message to sign: ephemeral_client_private_key | server_nonce                                                
    unsigned int clear_message_size =  ephemeral_public_key_size 
						                + CryptographyManager::getNonceSize();

	unsigned char* clear_message = (unsigned char*) 
									calloc(1, clear_message_size);
	if(clear_message == nullptr)
	{
		std::cout << "Error in calloc" << std::endl;
		exit(1);
	}

	// building the message to be signed 
	memcpy(clear_message, ephemeral_public_key, ephemeral_public_key_size);
	memcpy(clear_message + ephemeral_public_key_size, server_nonce, 
                                CryptographyManager::getNonceSize());

    // build the private key filename concatenating the prefix, the username
    // and the suffix
    char* private_key_filename = (char*) 
									calloc(1, MAX_PRIVATE_KEY_FILENAME_SIZE);
    strcpy(private_key_filename, PRIVATE_KEY_FILENAME_PREFIX);
    strcat(private_key_filename, username);
    strcat(private_key_filename, PRIVATE_KEY_FILENAME_SUFFIX);
	
	signature = CryptographyManager::signMessage(clear_message, 
				clear_message_size, private_key_filename, signature_size);
	
    unsigned char* final_message = 
                    (unsigned char*)calloc(1, MAX_FINAL_HANDSHAKE_MESSAGE_SIZE);

    if (final_message == nullptr) 
    {
        std::cout << "Error in hello packet calloc\n";
        exit(1);
    }

    unsigned int final_message_size = getFinalMessage(final_message);

    sendPacket(final_message, final_message_size);

    free(clear_message);
    free(private_key_filename);
	free(final_message);
}

void ClientConnectionManager::setSharedKey()
{
	// derive shared secret that will be used to derive the session key
	size_t shared_secret_size;
	unsigned char* shared_secret = CryptographyManager::getSharedSecret
											(ephemeral_private_key,
											deserialized_ephemeral_server_key,
											&shared_secret_size);
    
    // derive session key
	shared_key = CryptographyManager::getSharedKey(shared_secret, 
													shared_secret_size);
}

unsigned int ClientConnectionManager::getFinalMessage
												(unsigned char* final_message)
{
	Serializer serializer = Serializer(final_message);

    // final_message: 
    // key_size | key | signature_size | signature
	serializer.serializeInt(ephemeral_public_key_size);
	serializer.serializeByteStream(ephemeral_public_key, 
									ephemeral_public_key_size);
    serializer.serializeInt(signature_size);
    serializer.serializeByteStream(signature, signature_size);
                        
	return serializer.getOffset();	
}


void ClientConnectionManager::receiveFinalMessage()
{
    unsigned char* final_message = nullptr;
	receivePacket(final_message);

    Deserializer deserializer = Deserializer(final_message);

	unsigned char* plaintext;
	unsigned int plaintext_size;
	parseReceivedMessage(deserializer, plaintext, plaintext_size);
    message_counter++;
    
	if(!areBuffersEqual(plaintext, plaintext_size, 
						(unsigned char*) ACK_MESSAGE, strlen(ACK_MESSAGE) + 1))
	{
		std::cout << "Error: expected " << ACK_MESSAGE << std::endl;
        std::cout << "Received: ";
        printBuffer(plaintext, plaintext_size);
		exit(1);
	}

}


void ClientConnectionManager::showMenu()
{
    std::cout << std::endl 
              << "+-+-+-+-+-+-+-+-+-+-+-+-+" << std::endl
              << "|S|e|c|u|r|e|-|C|l|o|u|d|" << std::endl
              << "+-+-+-+-+-+-+-+-+-+-+-+-+" << std::endl
              << std::endl;
    
    std::cout << "Welcome, " << username << "! Please, select an operation:"
    << std::endl
    << "\t- upload: ..." << std::endl
    << "\t- download: ..." << std::endl
    << "\t- delete: ..." << std::endl
    << "\t- list: it prints the list of the filenames of the available files" <<
		 "in your dedicated storage" << std::endl
    << "\t- rename: ..." << std::endl
    << "\t- logout: ..." << std::endl
    << std::endl
    << ">";
}


void ClientConnectionManager::retrieveCommand()
{
    bool logout_exit = false;
    while(!logout_exit)
    {
        showMenu();
        std::string command;
        std::getline(std::cin, command);
        if(!std::cin)
        {
            std::cout << "Error in reading command" << std::endl;
            exit(1);
        }
        
        std::cout << "DBG: you typed: " << command << std::endl;

		// TO DO: security check on the inserted command

        if(command == "upload")
        {
            uploadFile();
        } 
        else if(command == "download")
        {
            downloadFile();
        }
        else if(command == "delete")
        {
            deleteFile();
        }
        else if(command == "list")
        {
            printFilenamesList();
        } 
        else if(command == "rename")
        {
            renameFile();
        }
        else if(command == "logout")
        {
            logout();
            logout_exit = true;
        }
        else
        {
            std::cout << "Error in parsing the command" << std::endl;
            exit(1);
        }
    }
}

void ClientConnectionManager::uploadFile()
{

}


void ClientConnectionManager::downloadFile()
{
    std::cout << "DBG: starting the downloadFile() routine" << std::endl;
    unsigned int request_message_size;
    std::cout << "getMessageToSend() call" << std::endl;
	unsigned char* request_message = getMessageToSend
											((unsigned char*)"prova.txt", 
											request_message_size, 
											DOWNLOAD_OPERATION_CODE);
    std::cout << "getMessageToSend() called" << std::endl;
    std::cout << "Sending packet" << std::endl;
	sendPacket(request_message, request_message_size);
	message_counter++;
    std::cout << "packet sent" << std::endl;
}


void ClientConnectionManager::deleteFile()
{
    
}


void ClientConnectionManager::printFilenamesList()
{
	unsigned int request_message_size;
	// TO DO: insert in a file of constants
	unsigned char* request_message = getMessageToSend
											((unsigned char*)OPERATION_MESSAGE, 
											request_message_size, 
											LIST_OPERATION_CODE);
	sendPacket(request_message, request_message_size);
	message_counter++;
}


void ClientConnectionManager::renameFile()
{
    
}


void ClientConnectionManager::logout()
{
    
}

