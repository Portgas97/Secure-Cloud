#include "ServerConnectionManager.h"

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
	close(socket_fd);
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
	{
		std::cout << "Connection accepted, serving client..." << std::endl;
        serveClient(client_socket);
		std::cout << "Client served, closing." << std::endl;
	}

}

/*
	it first performs the handshake with the client connected to client_socket,
	then it shows it a menu, receives its requests and serves them
*/
void ServerConnectionManager::serveClient(int client_socket)
{
	ServerConnectionManager request_handler =
 										ServerConnectionManager(client_socket);
	request_handler.handleHandshake();
	unsigned int has_user_logged_out = 0;
	while(!has_user_logged_out)   
		has_user_logged_out = request_handler.handleRequest(); 
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
void ServerConnectionManager::handleHandshake()
{
	receiveHello();
	sendHello();
	receiveFinalHandshakeMessage();
	setSharedKey();
	sendAckMessage();
}


/*
    it receives and parses client hello packet and sends back server 
	hello packet
*/
void ServerConnectionManager::receiveHello()
{
	unsigned char* hello_packet = nullptr;
	receivePacket(hello_packet);

	// get each hello_packet field
	Deserializer deserializer = Deserializer(hello_packet);
		
	// received_packet: username_size | username | nonce_size | nonce
	logged_username_size = deserializer.deserializeInt();

	char* received_logged_username = (char*)calloc(1, 
												logged_username_size);

	if(received_logged_username == nullptr)
	{
		std::cout << "Error in calloc" << std::endl;
		exit(1);
	}

	deserializer.deserializeString(received_logged_username, 
									logged_username_size);

	if(UtilityManager::isUserPresent(received_logged_username, USERS_DIRECTORY) 
																	== false)
	{
		std::cout << "Error: the username does not exist" << std::endl;
		exit(1);
	}
	
	strncpy(logged_username, received_logged_username, logged_username_size);	

	unsigned int client_nonce_size = deserializer.deserializeInt();

	if(client_nonce_size != CryptographyManager::getNonceSize())
	{
		std::cout << "Error in nonce size reception" << std::endl;
		exit(1);
	}

	client_nonce = (unsigned char*) calloc(1, client_nonce_size);

	if(client_nonce == nullptr)
	{
		std::cout << "Error in calloc" << std::endl;
		exit(1);
	}

	deserializer.deserializeByteStream(client_nonce, client_nonce_size);

	free(hello_packet);
}


/*
    it creates the hello packet and returns it.
    It returns also the hello packet size
*/
unsigned int ServerConnectionManager::getHelloPacket(unsigned char* hello_packet)
{
	Serializer serializer = Serializer(hello_packet);

    // nonce_size | nonce | certificate_size | certificate | key_size | key
    // signature_size | signature
	serializer.serializeInt(CryptographyManager::getNonceSize());
	serializer.serializeByteStream(server_nonce, 
									CryptographyManager::getNonceSize());
	serializer.serializeInt(certificate_size);
	serializer.serializeByteStream(certificate, certificate_size);
	serializer.serializeInt(ephemeral_public_key_size);
	serializer.serializeByteStream(ephemeral_public_key, 
													ephemeral_public_key_size);
	serializer.serializeInt(signature_size);
	serializer.serializeByteStream(signature, signature_size);														

	return serializer.getOffset();	
}

/* 
	It builds and sends the hello packet, which has the following structure
	hello packet:
	//  nonce_size   | nonce | certificate_size  | certificate   | 
    //  key_size     | key   | signature_size    | signature     |
*/
void ServerConnectionManager::sendHello()
{
	server_nonce = (unsigned char*)calloc(1,
										CryptographyManager::getNonceSize());

	if(server_nonce == nullptr)
	{
		std::cout << "Error in calloc" << std::endl;
		exit(1);
	}
	// get nonce
    CryptographyManager::getRandomBytes(server_nonce, 
										CryptographyManager::getNonceSize());

	certificate = UtilityManager::getCertificateFromFile(CERTIFICATE_FILENAME, 
														certificate_size);

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
	memcpy(clear_message + ephemeral_public_key_size, client_nonce, 
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

void ServerConnectionManager::receiveFinalHandshakeMessage()
{
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

	// read the client public key from file

    // build the client public key filename concatenating the prefix, 
	// the client username and the suffix
    char* client_certificate_filename = (char*)
								calloc(1, MAX_CLIENT_CERTIFICATE_FILENAME_SIZE);
	if(client_certificate_filename == nullptr)
	{
		std::cout << "Error in calloc" << std::endl;
		exit(1);
	}

    strcpy(client_certificate_filename, CLIENT_CERTIFICATE_FILENAME_PREFIX);
    strcat(client_certificate_filename, logged_username);
    strcat(client_certificate_filename, CLIENT_CERTIFICATE_FILENAME_SUFFIX);

	unsigned int client_certificate_size;
	unsigned char* client_certificate = UtilityManager::getCertificateFromFile
										(client_certificate_filename,
										client_certificate_size);

	X509* deserialized_client_certificate = 
							CryptographyManager::deserializeCertificate
								(client_certificate, client_certificate_size);

	CryptographyManager::verifySignature(client_signature,client_signature_size, 
                            clear_message, clear_message_size, 
                            X509_get_pubkey(deserialized_client_certificate));

	free(client_certificate);	
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
												
void ServerConnectionManager::sendAckMessage()
{
	unsigned int message_size;
	unsigned char* message = getMessageToSend((unsigned char*)ACK_MESSAGE, 
												message_size);
	sendPacket(message, message_size);
	free(message);
}


const char* ServerConnectionManager::canonicalizeUserPath(const char* file_path)
{
	const char* canonicalized_filename = realpath(file_path, nullptr);

	if(canonicalized_filename == nullptr)
	{
		std::cout << "Wrong path" << std::endl;
		return nullptr;
	}

	std::string correct_directory = std::string(BASE_PATH) + 
							std::string(CLIENT_STORAGE_DIRECTORY_NAME_PREFIX) + 
							std::string(logged_username) + 
							std::string(CLIENT_STORAGE_DIRECTORY_NAME_SUFFIX);

	if(strncmp(canonicalized_filename, correct_directory.c_str(), 
											correct_directory.size()) != 0)
	{
		std::cout << "Unauthorized path" << std::endl;
		// TO DO: changed from exit(1)
		return nullptr;
	}

	return canonicalized_filename;
}


/*
	It receives request from client and select the operation it choose.
	It returns 0 if the user has not logged out, 1 otherwise
*/
unsigned int ServerConnectionManager::handleRequest()
{
	if(message_counter == UINT32_MAX)
	{
		std::cout << "Error: message counter overflow" << std::endl;
		exit(1);
	}
	
	std::cout << "Waiting for the next operation..." << std::endl;
	std::string command = getRequestCommand();

	unsigned int command_first_delimiter_position = 
								command.find(" ") >= command.length() ? 
								command.length() - 1: command.find(" ");

	std::string operation = command.substr(0, command_first_delimiter_position);

	if(operation == DOWNLOAD_MESSAGE)
	{
		std::string filename = command.substr
									(command_first_delimiter_position + 1,
									command.length() - 
									command_first_delimiter_position - 1);

		std::string file_path = CLIENT_STORAGE_DIRECTORY_NAME_PREFIX;
		file_path += logged_username;
		file_path += CLIENT_STORAGE_DIRECTORY_NAME_SUFFIX;
		file_path += filename;

		const char* canonicalized_filename =
									canonicalizeUserPath(file_path.c_str());

		if(canonicalized_filename == nullptr)
		{
			std::cout << "The file does not exist" << std::endl;
			sendError();
			return 0;
		}
		
		handleDownloadOperation(canonicalized_filename);
	}
	else if(operation == LIST_MESSAGE)
	{
		handleListOperation();
	}
	else if(operation == UPLOAD_MESSAGE || operation == LAST_UPLOAD_MESSAGE)
	{
		unsigned int command_second_delimiter_position = 
					command.find(" ", command_first_delimiter_position + 1) >= 
					command.length() ? 
					command.length() - 1 : 
					command.find(" ", command_first_delimiter_position + 1);
		std::string filename = command.substr
									(command_first_delimiter_position + 1,
									command_second_delimiter_position - 
									command_first_delimiter_position - 1);

		if(UtilityManager::isFilenameValid(filename) == false)
		{
		 	std::cout << "Error: the new filename is not valid" << std::endl;
		 	exit(1);
		}

		std::string file_path = CLIENT_STORAGE_DIRECTORY_NAME_PREFIX;
		file_path += logged_username;
		file_path += CLIENT_STORAGE_DIRECTORY_NAME_SUFFIX;
		file_path += filename;

		std::string file_content = command.substr
										(command_second_delimiter_position + 1,
										command.length() - 
										command_second_delimiter_position - 1);

		handleUploadOperation(operation, file_path, 
								(unsigned char*)file_content.c_str(), 
								file_content.length() - 1);
	}
	else if(operation == DELETE_MESSAGE)
	{
		std::string filename = command.substr
									(command_first_delimiter_position + 1,
									command.length() - 
									command_first_delimiter_position - 1);

		std::string file_path = CLIENT_STORAGE_DIRECTORY_NAME_PREFIX;
		file_path += logged_username;
		file_path += CLIENT_STORAGE_DIRECTORY_NAME_SUFFIX;
		file_path += filename;

		const char* canonicalized_filename =
										canonicalizeUserPath(file_path.c_str());

		if(canonicalized_filename == nullptr)
		{
			std::cout << "The file does not exist" << std::endl;
			sendError();
			return 0;
		}

		handleDeleteOperation(file_path);	
	}
	else if(operation == LOGOUT_MESSAGE)
	{
		handleLogoutOperation();
		return 1;
	}
	else if(operation == RENAME_MESSAGE)
	{
		unsigned int command_second_delimiter_position = 
					command.find(" ", command_first_delimiter_position + 1) >= 
					command.length() ? 
					command.length() - 1 : 
					command.find(" ", command_first_delimiter_position + 1);
		std::string original_filename = command.substr
									(command_first_delimiter_position + 1,
									command_second_delimiter_position - 
									command_first_delimiter_position - 1);

		std::string original_file_path = CLIENT_STORAGE_DIRECTORY_NAME_PREFIX;
		original_file_path += logged_username;
		original_file_path += CLIENT_STORAGE_DIRECTORY_NAME_SUFFIX;
		original_file_path += original_filename;

		const char* canonicalized_original_filename = 
								canonicalizeUserPath(original_file_path.c_str());

		if(canonicalized_original_filename == nullptr)
		{
			std::cout << "The file does not exist" << std::endl;
			sendError(); 
			return 0;
		}

		std::string new_filename = command.substr
										(command_second_delimiter_position + 1,
										command.length() - 
										command_second_delimiter_position - 2);


		if(UtilityManager::isFilenameValid(new_filename) == false)
		{
		 	std::cout << "Error: the new filename is not valid" << std::endl;
			sendError();
		 	exit(1);
		}


		std::string new_file_path = CLIENT_STORAGE_DIRECTORY_NAME_PREFIX;
		new_file_path += logged_username;
		new_file_path += CLIENT_STORAGE_DIRECTORY_NAME_SUFFIX;
		
		new_file_path += new_filename;
		handleRenameOperation(canonicalized_original_filename, new_file_path);

	}
	else
	{
		std::cout << "Error in command received" << std::endl;
		exit(1);
	}
	
	return 0;
}




/*
	It parses the received packet, checks if everything is correct and then
	replies with the filenames list
*/
void ServerConnectionManager::handleListOperation()
{

	// building user's dedicated directory path
	std::string directory_name = CLIENT_STORAGE_DIRECTORY_NAME_PREFIX;
	directory_name += logged_username;
	directory_name += CLIENT_STORAGE_DIRECTORY_NAME_SUFFIX;

	std::string directory_filenames = 
						UtilityManager::getDirectoryFilenames(directory_name);

	std::string plaintext = std::string(LIST_MESSAGE) + std::string(" ") + 
							directory_filenames;
	
	unsigned int message_size;
	unsigned char* message = getMessageToSend
								((unsigned char*)plaintext.c_str(), 
								message_size);

	sendPacket(message, message_size);
}


void ServerConnectionManager::handleDownloadOperation(std::string filename)
{
	if(sendFileContent(filename, DOWNLOAD_MESSAGE) == -1)
	{
		std::cout << "Error in send file content" << std::endl;
		sendError();
	}
}


void ServerConnectionManager::handleUploadOperation(std::string operation, 
											std::string filename,
											unsigned char* file_content_buffer,
											unsigned int file_content_size)
{
	if(UtilityManager::storeFileContent(filename, file_content_buffer, 
													file_content_size) == -1)
	{
		std::cout << "Error in store file content" << std::endl;
		sendError();
		return;
	}

	std::string command, file_content;
	unsigned int command_first_delimiter_position;
	while(operation == UPLOAD_MESSAGE)
	{
		command = getRequestCommand();
		command_first_delimiter_position = 
									command.find(" ") >= command.length() ? 
									command.length() - 1: command.find(" ");

		operation = command.substr(0, command_first_delimiter_position);
		
		file_content = command.substr(command_first_delimiter_position + 1,
										command.length() - 
										command_first_delimiter_position - 1);
		file_content_size = file_content.length();

		// store the next file chunk
		if(UtilityManager::storeFileContent(filename, 
				(unsigned char*)file_content.c_str(), file_content_size) == -1)
		{
				std::cout << "Error in store file content" << std::endl;
				sendError();
				return;
		}

	}	

	// send ACK
	sendAckMessage();
}


void ServerConnectionManager::handleRenameOperation
												(const char* original_filename, 
												std::string new_filename)
{
	rename(original_filename, new_filename.c_str());
	
	// send ACK
	sendAckMessage();
}
	
void ServerConnectionManager::handleDeleteOperation(std::string filename)
{
	// remove the file if actually exists
	if(UtilityManager::fileAlreadyExists(filename))
		std::experimental::filesystem::remove(filename);

	else
	{	
		std::cout << "Error: the file the client wants to delete does " << 
					"not exist" << std::endl;
		sendError();
		return;
	}

	// send ACK
	sendAckMessage();
}

void ServerConnectionManager::handleLogoutOperation()
{
	destroyConnection();
	CryptographyManager::deleteSharedKey(shared_key);
	sendAckMessage();
}


void ServerConnectionManager::sendError()
{
	unsigned int message_size;
	unsigned char* message = getMessageToSend((unsigned char*)ERROR_MESSAGE, 
																message_size);
	sendPacket(message, message_size);
}
