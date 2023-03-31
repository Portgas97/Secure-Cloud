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
    close(socket_fd);
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

	if(UtilityManager::isUserPresent(username, USERS_DIRECTORY) == false)
	{
		std::cout << "Error: the username you inserted does not exist" 
					<< std::endl;
		exit(1);
	}

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
	sendFinalHandshakeMessage();
	setSharedKey();
	receiveAckMessage();
}


/*
    it creates the hello packet and returns it.
    It returns the hello packet size
*/
void ClientConnectionManager::getHelloPacket(unsigned char* hello_packet)
{
	Serializer serializer = Serializer(hello_packet);

    // hello_packet: username_size | username | nonce_size | nonce
	serializer.serializeInt(strlen(username) + 1);
 	serializer.serializeString(username, strlen(username) + 1);
	serializer.serializeInt(CryptographyManager::getNonceSize());
	serializer.serializeByteStream(client_nonce, 
                                        CryptographyManager::getNonceSize());

	
}


/*
    it creates the client nonce, the client hello and sends the client
    hello to the server
*/
void ClientConnectionManager::sendHello()
{
	std::cout << "Starting the handshake" << std::endl;
	client_nonce = (unsigned char*) calloc(1, 
							CryptographyManager::getNonceSize());

	if(client_nonce == nullptr)
	{
		std::cout << "Error in calloc" << std::endl;
		exit(1);
	}

    CryptographyManager::getRandomBytes(client_nonce,
							CryptographyManager::getNonceSize());

	unsigned int hello_packet_size = 
                    sizeof(MAX_USERNAME_SIZE) 
                    + MAX_USERNAME_SIZE 
                    + sizeof(CryptographyManager::getNonceSize()) 
                    + CryptographyManager::getNonceSize();

    // hello_packet: username_size | username | nonce_size | nonce
    unsigned char* hello_packet = (unsigned char*)calloc(1, hello_packet_size);

    if (hello_packet == nullptr) 
    {
        std::cout << "Error in hello packet calloc\n";
        exit(1);
    }

    getHelloPacket(hello_packet);

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

	// TO DO for more security, is OK?
	CryptographyManager::unoptimizedMemset(ephemeral_server_key, 
												ephemeral_server_key_size);
												
	X509_free(deserialized_server_certificate);
	free(ephemeral_server_key);
    free(server_certificate);
	free(server_signature);
	free(clear_message);
    free(hello_packet);
}

void ClientConnectionManager::sendFinalHandshakeMessage()
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
	
	unsigned int final_handshake_message_size =                                 
                                sizeof(ephemeral_public_key_size)
                                + ephemeral_public_key_size
                                + sizeof(signature_size)
                                + signature_size;
    unsigned char* final_message = 
                    (unsigned char*)calloc(1, final_handshake_message_size);

    if (final_message == nullptr) 
    {
        std::cout << "Error in hello packet calloc\n";
        exit(1);
    }

    unsigned int final_message_size = getFinalMessage(final_message);

    sendPacket(final_message, final_message_size);

	CryptographyManager::unoptimizedMemset(ephemeral_public_key, ephemeral_public_key_size);
	free(ephemeral_public_key);
	free(signature);
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
    EVP_PKEY_free(deserialized_ephemeral_server_key);
    
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


void ClientConnectionManager::receiveAckMessage()
{
    unsigned char* final_message = nullptr;
	receivePacket(final_message);

    Deserializer deserializer = Deserializer(final_message);

	unsigned int plaintext_size;
	unsigned char* plaintext = parseReceivedMessage(deserializer, 
													plaintext_size);

	if(!UtilityManager::areBuffersEqual(plaintext, plaintext_size, 
				(unsigned char*) ACK_MESSAGE, strlen(ACK_MESSAGE) + 1))
	{
		std::cout << "Error during operation" << std::endl;
		return;
	}
	std::cout << "Operation successfully completed" << std::endl;

	free(final_message);
	free(plaintext);
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

    << "\t- upload <filename>: upload a local file on the server" << std::endl

    << "\t- download <filename>: download an existing file from the server, "
	<< "ask confirmation for overwriting a local file" << std::endl

    << "\t- delete <filename>: delete an existing file from the server" << std::endl

    << "\t- list: print the list of the filenames of the available files " <<
		 "in your dedicated storage" << std::endl

    << "\t- rename <original_filename> <new_filename>: rename an existing " <<
		"file named original_filename in new_filename" << std::endl

    << "\t- logout: close the connection to Secure Cloud" << std::endl

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

		unsigned int command_first_delimiter_position = 
									command.find(" ") >= command.length() ? 
									command.length(): command.find(" ");
		std::string operation = command.substr(0, 
											command_first_delimiter_position);

        
        if(operation == "upload")
        {
			if(command_first_delimiter_position + 1 > command.size())
			{
				std::cout << "Argument is missing!" << std::endl;
				continue;
			}
			
			// take the filename argument
			std::string filename = command.substr
										(command_first_delimiter_position + 1,
										command.length() -
										command_first_delimiter_position - 1);

			if(!UtilityManager::isFilenameValid(filename))
			{
				std::cout << "Filename is not valid" << std::endl;
				continue;
			}

			// build the file path
			std::string file_path = STORAGE_DIRECTORY_NAME_PREFIX;
			file_path += username;
			file_path += STORAGE_DIRECTORY_NAME_SUFFIX;
			file_path += filename;
            uploadFile(file_path);

			// receive ack
			//receiveAckMessage();
        } 
        else if(operation == "download")
        {
			// take the filename argument
			if(command_first_delimiter_position + 1 > command.size())
			{
				std::cout << "Argument is missing!" << std::endl;
				continue;
			}
			std::string filename = command.substr
										(command_first_delimiter_position + 1,
										command.length() -
										command_first_delimiter_position - 1);

			if(!UtilityManager::isFilenameValid(filename))
			{
				std::cout << "Filename is not valid" << std::endl;
				continue;
			}

			// build the file path
			std::string file_path = STORAGE_DIRECTORY_NAME_PREFIX;
			file_path += username;
			file_path += STORAGE_DIRECTORY_NAME_SUFFIX;
			file_path += filename;
			

            downloadFile(file_path);
        }
        else if(operation == "delete")
        {
			// TO DO specifications say to ask for confirmation
			if(command_first_delimiter_position + 1 > command.size())
			{
				std::cout << "Argument is missing!" << std::endl;
				continue;
			}
			
			// take the filename argument
			std::string filename = command.substr
										(command_first_delimiter_position + 1,
										command.length() -
										command_first_delimiter_position - 1);
			
			if(!UtilityManager::isFilenameValid(filename))
			{
				std::cout << "Filename is not valid" << std::endl;
				continue;
			}

			std::cout << "Are you sure you want to delete" << filename 
						<< "? yes/no: ";
			std::string confirm;
			std::getline(std::cin, confirm);
			if(!std::cin)
			{
				std::cout << "Error in reading command" << std::endl;
				exit(1);
			}
			if(confirm != "yes")
			{
				std::cout << "Discard the delete operation" << std::endl;
				continue;
			}

			// build the file path
			std::string file_path = STORAGE_DIRECTORY_NAME_PREFIX;
			file_path += username;
			file_path += STORAGE_DIRECTORY_NAME_SUFFIX;
			file_path += filename;

			
            deleteFile(file_path);

			// receive ack
			receiveAckMessage();
        }
        else if(operation == "list")
        {
            printFilenamesList();
        } 
        else if(operation == "rename")
        {
			if(command_first_delimiter_position + 1 > command.size())
			{
				std::cout << "Argument is missing!" << std::endl;
				continue;
			}
			unsigned int command_second_delimiter_position = 
					command.find(" ", command_first_delimiter_position + 1) >= 
					command.length() ? 
					command.length() - 1 : 
					command.find(" ", command_first_delimiter_position + 1);

			if(command_second_delimiter_position + 1 > command.size())
			{
				std::cout << "Argument is missing!" << std::endl;
				continue;
			}

			std::string original_filename = command.substr
										(command_first_delimiter_position + 1,
										command_second_delimiter_position - 
										command_first_delimiter_position - 1);

			if(!UtilityManager::isFilenameValid(original_filename))
			{
				std::cout << "Filename is not valid" << std::endl;
				continue;
			}

			std::string original_file_path = STORAGE_DIRECTORY_NAME_PREFIX;
			original_file_path += username;
			original_file_path += STORAGE_DIRECTORY_NAME_SUFFIX;
			original_file_path += original_filename;

			std::string new_filename = command.substr
										(command_second_delimiter_position + 1,
										command.length() - 
										command_second_delimiter_position - 1);

			if(!UtilityManager::isFilenameValid(new_filename))
			{
				std::cout << "Filename is not valid" << std::endl;
				continue;
			}

	        renameFile(original_file_path, new_filename);

			std::string received_command = getRequestCommand();

			unsigned int received_command_first_delimiter_position = 
										received_command.find(" ") >= received_command.length() ? 
										received_command.length() - 1: received_command.find(" ");

			std::string received_operation = received_command.substr(0, received_command_first_delimiter_position);

			if(received_operation == ERROR_MESSAGE)
			{
				std::cout << "Error: file does not exist?" << std::endl;
				continue;
			} 
			else if(received_operation == ACK_MESSAGE)
				std::cout << "Operation successfully completed" << std::endl;
			else
				std::cout << "Error: expected ACK" << std::endl;
			
		}
	    else if(operation == "logout")
	    {
	        logout();
	        logout_exit = true;
	    }
	    else
	        std::cout << "Error in parsing the command" << std::endl;
	}
}



void ClientConnectionManager::uploadFile(std::string filename)
{
	// check counter overflow
 	if(message_counter == UINT32_MAX)
	{
		std::cout << "Error: message counter overflow" << std::endl;
		exit(1);
	}

	if(sendFileContent(filename, UPLOAD_MESSAGE) == -1)
	{
		std::cout << "Error in sending file" << std::endl;
		return;
	}

	std::string reply = getRequestCommand();

	unsigned int reply_first_delimiter_position = 
								reply.find(" ") >= reply.length() ? 
								reply.length() - 1: reply.find(" ");

	std::string operation = reply.substr(0, reply_first_delimiter_position);

	if(operation == ERROR_MESSAGE)
		std::cout << "Error in upload" << std::endl;
	else
		std::cout << "Operation successfully completed" << std::endl;

}


void ClientConnectionManager::downloadFile(std::string file_path)
{
	if(UtilityManager::fileAlreadyExists(file_path))
	{
		std::cout << "The file already exist, do you want to continue?" <<
																	" yes/no: ";
		std::string confirm;
		std::getline(std::cin, confirm);
        if(!std::cin)
        {
            std::cout << "Error in reading command" << std::endl;
            exit(1);
        }
		if(confirm != "yes")
		{
			std::cout << "Discard the download operation" << std::endl;
			return;
		}
	}

	std::experimental::filesystem::remove(file_path);

	// check counter overflow
 	if(message_counter == UINT32_MAX)
	{
		std::cout << "Error: message counter overflow" << std::endl;
		exit(1);
	}

	// with rfind I search the passed symbol from the end towards the start
	std::string filename = file_path.substr(file_path.rfind("/") + 1, 
											std::string::npos - 
											file_path.rfind("/") - 1);

	// +1 is for space character
	unsigned int download_message_size = strlen(DOWNLOAD_MESSAGE) + 1
										+ 1 // space character
										+ filename.length() + 1;
	unsigned char* download_message = (unsigned char*) calloc(1, 
														download_message_size);
	if(download_message == nullptr)
	{
		std::cout << "Error in calloc" << std::endl;
		exit(1);
	}

	// prepare fragment upload packet
	Serializer serializer = Serializer(download_message);

	serializer.serializeString((char*)DOWNLOAD_MESSAGE, 
												strlen(DOWNLOAD_MESSAGE));
	serializer.serializeChar(' ');
	serializer.serializeString((char*)filename.c_str(), filename.length());
	
	unsigned int message_size;
	unsigned char* message = getMessageToSend(download_message,
														message_size);
	free(download_message);
	sendPacket(message, message_size);
	free(message);


	std::string operation;
	std::string command = getRequestCommand();

	// std::cout << "DBG command: " << command << std::endl;

	unsigned int command_first_delimiter_position = 
								command.find(" ") >= command.length() ? 
								command.length() - 1: command.find(" ");

	operation = command.substr(0, command_first_delimiter_position);

	if(operation == ERROR_MESSAGE)
	{
		std::cout << "Error: file does not exist?" << std::endl;
		return;
	}

	unsigned int command_second_delimiter_position = 
				command.find(" ", command_first_delimiter_position + 1) >= 
				command.length() ? 
				command.length() - 1 : 
				command.find(" ", command_first_delimiter_position + 1);

	std::string received_filename = command.substr
									(command_first_delimiter_position + 1,
									command_second_delimiter_position - 
									command_first_delimiter_position - 1);
	
	std::string file_content = command.substr
									(command_second_delimiter_position + 1,
									command.length() - 
									command_second_delimiter_position - 1);
	
	// std::cout << "DBG filename: " << received_filename << std::endl;
	// std::cout << "DBG file_content: " << file_content << std::endl;

	UtilityManager::storeFileContent(file_path, 
				(unsigned char*)file_content.c_str(), file_content.length());

	while(operation == DOWNLOAD_MESSAGE)
	{
		command = getRequestCommand();

		// std::cout << "DBG command: " << command << std::endl;

		command_first_delimiter_position = 
									command.find(" ") >= command.length() ? 
									command.length() - 1: command.find(" ");

		operation = command.substr(0, command_first_delimiter_position);

		file_content = command.substr
									(command_first_delimiter_position + 1,
									command.length() - 
									command_first_delimiter_position - 1);
		// std::cout << "DBG file_content: " << file_content << std::endl;

		UtilityManager::storeFileContent(file_path, 
				(unsigned char*)file_content.c_str(), file_content.length());
	}

	std::cout << "Operation successfully completed" << std::endl;

	
}


void ClientConnectionManager::deleteFile(std::string file_path)
{
	// check counter overflow
 	if(message_counter == UINT32_MAX)
	{
		std::cout << "Error: message counter overflow" << std::endl;
		exit(1);
	}

	// with rfind I search the passed symbol from the end towards the start
	std::string filename = file_path.substr(file_path.rfind("/") + 1, 
											std::string::npos - 
											file_path.rfind("/") - 1);

	// +1 is for space character
	unsigned int delete_message_size = strlen(DELETE_MESSAGE) + 1 +
										1 +
										filename.length() + 1;
	unsigned char* delete_message = 
								(unsigned char*) calloc(1, delete_message_size);
	if(delete_message == nullptr)
	{
		std::cout << "Error in calloc" << std::endl;
		exit(1);
	}

	// prepare fragment upload packet
	Serializer serializer = Serializer(delete_message);

	serializer.serializeString((char*)DELETE_MESSAGE, strlen(DELETE_MESSAGE));
	serializer.serializeChar(' ');
	serializer.serializeString((char*)filename.c_str(), filename.length());

	unsigned int message_size;
	unsigned char* message = getMessageToSend(delete_message,
														message_size);
	sendPacket(message, message_size);
	free(message);
	free(delete_message);
}


void ClientConnectionManager::printFilenamesList()
{
	// check counter overflow
 	if(message_counter == UINT32_MAX)
	{
		std::cout << "Error: message counter overflow" << std::endl;
		exit(1);
	}

	unsigned int request_message_size;
	unsigned char* request_message = getMessageToSend
											((unsigned char*)LIST_MESSAGE, 
											request_message_size);
	// send the request
	sendPacket(request_message, request_message_size);
	free(request_message);

	std::string command = getRequestCommand();

	unsigned int command_first_delimiter_position = 
								command.find(" ") >= command.length() ? 
								command.length() - 1: command.find(" ");

	std::string operation = command.substr(0, command_first_delimiter_position);

	if(operation == ERROR_MESSAGE)
	{
		std::cout << "Error in list operation" << std::endl;
		return;
	}

	std::string files_list = command.substr
									(command_first_delimiter_position + 1,
									command.length() - 
									command_first_delimiter_position - 1);


	std::cout << "Files list: " << std::endl;
	std::cout << files_list;

}


void ClientConnectionManager::renameFile(std::string original_file_path,
										std::string new_filename)
{
	// check counter overflow
 	if(message_counter == UINT32_MAX)
	{
		std::cout << "Error: message counter overflow" << std::endl;
		exit(1);
	}

	// TO DO: check if the file exists

	// with rfind I search the passed symbol from the end towards the start
	std::string original_filename = 
					original_file_path.substr(original_file_path.rfind("/") + 1, 
											std::string::npos - 
											original_file_path.rfind("/") - 1);
	// +1 is for space characters
	unsigned int rename_message_size = strlen(RENAME_MESSAGE) + 
										1 +
										original_filename.length() + 1 +
										1 + 
										new_filename.length() + 1;
	unsigned char* rename_message = 
								(unsigned char*) calloc(1, rename_message_size);
	if(rename_message == nullptr)
	{
		std::cout << "Error in calloc" << std::endl;
		exit(1);
	}

	// prepare fragment upload packet
	Serializer serializer = Serializer(rename_message);

	serializer.serializeString((char*)RENAME_MESSAGE, strlen(RENAME_MESSAGE));
	serializer.serializeChar(' ');
	serializer.serializeString((char*)original_filename.c_str(), 
								original_filename.length());
	serializer.serializeChar(' ');
	serializer.serializeString((char*)new_filename.c_str(), 
								new_filename.length());

	unsigned int message_size;
	unsigned char* message = getMessageToSend(rename_message,
														message_size);
	sendPacket(message, message_size);
	free(rename_message);
	free(message);
}


void ClientConnectionManager::logout()
{
    // check counter overflow
 	if(message_counter == UINT32_MAX)
	{
		std::cout << "Error: message counter overflow" << std::endl;
		exit(1);
	}

	unsigned int request_message_size;
	unsigned char* request_message = getMessageToSend
											((unsigned char*)LOGOUT_MESSAGE, 
											request_message_size);
	sendPacket(request_message, request_message_size);
	free(request_message);

	receiveAckMessage();

	destroyConnection();

	CryptographyManager::deleteSharedKey(shared_key);
	
}

