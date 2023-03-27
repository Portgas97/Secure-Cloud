#include "ConnectionManager.h"

ConnectionManager::ConnectionManager()
{
        
}

ConnectionManager::~ConnectionManager()
{
    
}

// TO DO: move in utility class
void ConnectionManager::printBuffer(unsigned char* buffer, unsigned int buffer_size)
{
    for(unsigned int i = 0; i < buffer_size; i++)
        std::cout << buffer[i];

    std::cout << std::endl;
}

// TO DO: move in utility class
/*
	It compares two byteStreams and returns 1 if they are equal, 0 otherwise
*/
unsigned int ConnectionManager::areBuffersEqual(unsigned char* buffer1, 
										unsigned int buffer1_size,
										unsigned char* buffer2,
										unsigned int buffer2_size)
{
	if(buffer1_size != buffer2_size)
		return 0;

    for(unsigned int i = 0; i < buffer1_size; i++)
		if(buffer1[i] != buffer2[i])
			return 0;

	return 1;
}

/*
    it receives packet from the sender by receiving first the packet size, then
    the data packet and it returns the received data packet
*/
void ConnectionManager::receivePacket(unsigned char* &packet)
{
    uint32_t packet_size;
    int return_value = recv(socket_fd, (void*)&packet_size, 
							sizeof(uint32_t), 0);

    if(return_value <= 0)
    {
        std::cout << "Error in recv" << std::endl;
        exit(1);
    }
    
    packet_size = ntohl(packet_size);

    if(return_value < (int)sizeof(uint32_t))
    {
        std::cout << "Received " << return_value << " bytes instead of " 
                    << sizeof(uint32_t) << std::endl;
        exit(1);
    }

    //allocate needed memory space for the packet
    unsigned char* received_packet = (unsigned char*) calloc(1, packet_size);
    if(received_packet == nullptr)
    {
        std::cout << "Error in packet calloc" << std::endl;
        exit(1);
    }

    uint32_t received_bytes = 0;


    // hendle fragmented reception
    while(received_bytes < packet_size)
    {
        return_value = recv(socket_fd, (void*)received_packet, packet_size,  
                                                    MSG_WAITALL);

        if(return_value <= 0)
        {
            std::cout << "Error in recv" << std::endl;
            exit(1);
        }

        received_bytes += return_value;
    }

    packet = received_packet;

}

/*
    it sends first the packet length, then the packet itself 
*/
void ConnectionManager::sendPacket(unsigned char* packet, 
                                    unsigned int packet_size)
{
	packet_size = htonl(packet_size);

    int return_value = send(socket_fd, (void*)&packet_size, 
									sizeof(uint32_t), 0);

    if (return_value < 0) 
    {
        std::cout << "Error in send" << std::endl;
        exit(1);
    }

    packet_size = ntohl(packet_size);

    uint32_t bytes_sent = 0;

	

    // handle fragmented send
    while (bytes_sent < packet_size)
    {
        return_value = send(socket_fd, (void*)(packet + bytes_sent), 
                            packet_size - bytes_sent, 0);

        if (return_value < 0) 
        {
            std::cout << "Error in send" << std::endl;
            exit(1);
        }

        bytes_sent += return_value;
    }
}

/*
	it returns the message to be sent containing aad | ciphertext | tag.
	It returns also the message_size as argument.
	If the operation_code is not set, it means the function has to prepare 
	an ACK message.
*/
unsigned char* ConnectionManager::getMessageToSend
												(unsigned char* plaintext, 
												unsigned int& message_size, 
												unsigned int plaintext_size) // default 0
{
	// check counter overflow
 	if(message_counter == UINT32_MAX)
	{
		std::cout << "Error: message counter overflow" << std::endl;
		exit(1);
	}
	
	if(!plaintext_size)
		plaintext_size = strlen((char*)plaintext) + 1;

	unsigned int initialization_vector_size = 	
							CryptographyManager::getInitializationVectorSize();

	unsigned char* initialization_vector = 
						(unsigned char*)calloc(1, initialization_vector_size);
	
	if(initialization_vector == nullptr)
	{
		std::cout << "Error in calloc" << std::endl;
		exit(1);
	}	

	CryptographyManager::getInitializationVector(initialization_vector);

	unsigned int aad_size;
	unsigned char* aad = CryptographyManager::getAad(initialization_vector,
													message_counter, aad_size);

	// packet to be send: AAD | ciphertext | tag
	// AAD: counter | initialization vector
	message_size = 
					sizeof(initialization_vector_size) 
					// AAD
					+ aad_size
					// CT
					+ sizeof(plaintext_size)
					+ plaintext_size
					// TAG
					+ sizeof(CryptographyManager::getTagSize())
					+ CryptographyManager::getTagSize();

	unsigned char* message = (unsigned char*) calloc(1, message_size);
	if(message == nullptr)
	{
		std::cout << "Error in calloc" << std::endl;
		exit(1);
	}

	
	// ciphertext will be long as the plaintext
	unsigned char* ciphertext = (unsigned char*) calloc(1, plaintext_size);
	if(ciphertext == nullptr)
	{
		std::cout << "Error in calloc" << std::endl;
		exit(1);
	}

	unsigned int tag_size = CryptographyManager::getTagSize();
	unsigned char* tag = (unsigned char*) calloc(1, tag_size);
	if(tag == nullptr)
	{
		std::cout << "Error in calloc" << std::endl;
		exit(1);
	}
 
	unsigned int ciphertext_size = 
				CryptographyManager::authenticateAndEncryptMessage
													(plaintext, plaintext_size,
													aad, aad_size,
													shared_key, 
													initialization_vector,
													initialization_vector_size,
													ciphertext, tag);
													
	if(plaintext_size != ciphertext_size)
	{
		std::cout << "Error: ciphertext and plaintext must have the same length"
				<< std::endl;
		exit(1);
	}

	Serializer serializer = Serializer(message);

	// AAD
	serializer.serializeInt(message_counter);
	serializer.serializeInt(initialization_vector_size);
	serializer.serializeByteStream(initialization_vector,
													initialization_vector_size);
	// CT
	serializer.serializeInt(ciphertext_size);
	serializer.serializeByteStream(ciphertext, ciphertext_size);
	// TAG
	serializer.serializeInt(tag_size);
	serializer.serializeByteStream(tag, tag_size);
	
	// already defined, this is used for DBG
	unsigned int serialized_final_message_size = serializer.getOffset();
	if(serialized_final_message_size != message_size)
	{
		std::cout << "Error in computing the size of the packet" << std::endl;
		exit(1);
	}

	free(aad);
	free(initialization_vector);
	free(tag);
	free(ciphertext);

	// TO DO: evaluate if it's ok put here the message_counter increment
	message_counter++;

	return message;
}

// TO DO: maybe the function name is misleading
/*
	It parses received message and check everything is correct, otherwise
	it exits.
*/
unsigned char* ConnectionManager::parseReceivedMessage(Deserializer deserializer,
											unsigned int& plaintext_size)
{
	unsigned int received_message_counter = deserializer.deserializeInt();
	
	// counters on server and client side must have the same value
	if(received_message_counter != message_counter)
	{
		std::cout << "Error: client counter different from server counter" 
					<< std::endl;
		exit(1);
	}

	unsigned int initialization_vector_size = deserializer.deserializeInt();
	if(initialization_vector_size != 
							CryptographyManager::getInitializationVectorSize())
	{
		std::cout << "Error: the initialization vector size is wrong" 
                  << std::endl;
		exit(1);
	}

    unsigned char* initialization_vector = 
                        (unsigned char*)calloc(1, initialization_vector_size);

    if(initialization_vector == nullptr)
    {
        std::cout << "Error in calloc" << std::endl;
        exit(1);
    }

    deserializer.deserializeByteStream(initialization_vector, 
                                                    initialization_vector_size);

	unsigned int ciphertext_size = deserializer.deserializeInt();

    unsigned char* ciphertext = (unsigned char*)calloc(1, ciphertext_size);
    if(ciphertext == nullptr)
    {
        std::cout << "Error in calloc" << std::endl;
        exit(1);
    }
    deserializer.deserializeByteStream(ciphertext, ciphertext_size);
	
	unsigned int tag_size = deserializer.deserializeInt();

	if(tag_size != CryptographyManager::getTagSize())
	{
		std::cout << "Error: the tag size is wrong" << std::endl;
		exit(1);
	}

    unsigned char* tag = (unsigned char*)calloc(1, tag_size);
    if(tag == nullptr)
    {
        std::cout << "Error in calloc" << std::endl;
        exit(1);
    }

    deserializer.deserializeByteStream(tag, tag_size);
	
	// the plaintext and the ciphertext must have the same size
    unsigned char* plaintext = (unsigned char*)calloc(1, ciphertext_size);
    if(plaintext == nullptr)
    {
        std::cout << "Error in calloc" << std::endl;
        exit(1);
    }

	unsigned int aad_size;
	unsigned char* aad = CryptographyManager::getAad(initialization_vector,
													message_counter, aad_size);

    if(aad == nullptr)
    {
        std::cout << "Error in calloc" << std::endl;
        exit(1);
    }


	plaintext_size = CryptographyManager::authenticateAndDecryptMessage
										(ciphertext, ciphertext_size, aad, 
										aad_size, tag, shared_key, 
										initialization_vector, 
                                        initialization_vector_size, plaintext);
	
	free(aad);
    free(tag);
    free(ciphertext);
    free(initialization_vector);

	// TO DO: evaluate if it's ok put here the message_counter increment
	message_counter++;

	return plaintext;
}

unsigned char* ConnectionManager::getSmallFileContent(FILE* file, 
													unsigned int file_size)
{
	unsigned char* buffer = (unsigned char*) 
											calloc(1, file_size);

	if(buffer == nullptr) 
	{ 
		std::cout << "Error in calloc" << std::endl; 
		exit(1); 
	}

	// actual read
	unsigned int return_value = fread(buffer, 1, file_size, file);

	if(return_value < file_size) 
	{ 
		std::cout << "Error in fread" << std::endl;
		exit(1); 
	}
	return buffer;
}

// TO DO: to insert in utility file
void ConnectionManager::sendFileContent(std::string file_path, int download)
{
	FILE* file = fopen(file_path.c_str(), "rb");
	if(file == nullptr)
	{
		std::cout << "Error in fopen" << std::endl;
		exit(1);
	}	

	// with rfind I search the passed symbol from the end towards the start
	std::string filename = file_path.substr(file_path.rfind("/") + 1, 
											std::string::npos - 
											file_path.rfind("/") - 1);

	// get file size
	// move the file pointer to the end of the file
	fseek(file, 0, SEEK_END);
	// returns the file pointer position
	unsigned int file_size = ftell(file);
	// move file pointer to the beginning of the file
	fseek(file, 0, SEEK_SET);

    if (file_size > UINT32_MAX) 
	{
		std::cout << "Error: the file is too big" << std::endl;
		exit(1);
    }

	unsigned long int sent_bytes = 0;
	unsigned int message_size;
	unsigned char* message = nullptr; 
	unsigned int fragment_size;
	unsigned char* fragment = nullptr;
	unsigned int message_to_send_size;
	unsigned char* message_to_send = nullptr;
	
    while (sent_bytes < file_size) 
	{
		// check if it's the last send
		if(file_size - sent_bytes >= CHUNK_SIZE)
		{	
			fragment_size = CHUNK_SIZE;
			if(download)
				message_size = strlen(DOWNLOAD_MESSAGE) + 1;
			else
				message_size = strlen(UPLOAD_MESSAGE) + 1;
		}
		else
		{
			// last send case
			fragment_size = file_size - sent_bytes;
			if(download)
				message_size = strlen(LAST_DOWNLOAD_MESSAGE) + 1;
			else
			message_size = strlen(LAST_UPLOAD_MESSAGE) + 1;			
		}

		// if it's the first send, add the filename to the request message
		if(sent_bytes == 0)
			message_size += filename.length() + 1;

		message_size += fragment_size;

		// +1 for the space character
		message = (unsigned char*) calloc(1, message_size + 1);
		if(message == nullptr)
		{
			std::cout << "Error in calloc" << std::endl;
			exit(1);
		}

		// prepare fragment upload packet
		Serializer serializer = Serializer(message);

		switch(download)
		{
			case 0:
				if(file_size - sent_bytes >= CHUNK_SIZE)
					serializer.serializeString((char*)UPLOAD_MESSAGE, 
													strlen(UPLOAD_MESSAGE));
				else
					serializer.serializeString((char*)LAST_UPLOAD_MESSAGE, 
												strlen(LAST_UPLOAD_MESSAGE));
				break;
			case 1:
				if(file_size - sent_bytes >= CHUNK_SIZE)
					serializer.serializeString((char*)DOWNLOAD_MESSAGE, 
												strlen(DOWNLOAD_MESSAGE));
				else
					serializer.serializeString((char*)LAST_DOWNLOAD_MESSAGE, 
												strlen(LAST_DOWNLOAD_MESSAGE));
				break;
			default:
				break;
		}

		if(sent_bytes == 0)
		{
			// serialize the space after the operation name
			serializer.serializeChar(' ');
			serializer.serializeString((char*)filename.c_str(), 
										filename.length());
		}

		fragment = (unsigned char*) calloc(1, fragment_size);
		if(fragment == nullptr)
		{
			std::cout << "Error in calloc" << std::endl;
			exit(1);
		}
		fragment = getSmallFileContent(file, fragment_size);

		serializer.serializeChar(' ');
		serializer.serializeByteStream(fragment, fragment_size);

		message_to_send = getMessageToSend(message, message_to_send_size, 
													serializer.getOffset());

		sendPacket(message_to_send, message_to_send_size);
							
		sent_bytes += fragment_size;
		free(fragment);
		free(message);
	}

	fclose(file);
}

// TO DO: insert in a utility file
void ConnectionManager::storeFileContent(std::string filename, 
												unsigned char* file_content,
												unsigned int file_content_size)
{
	// TO DO: canonicalize filename

	FILE* file = fopen(filename.c_str(), "wb");
	if(file == nullptr)
	{
		std::cout << "Error in fopen" << std::endl;
		exit(1);
	}

	unsigned int written_file_content_size = fwrite(file_content, 
													sizeof(unsigned char),
													file_content_size, 
													file);

	if(written_file_content_size >= UINT32_MAX || 
								written_file_content_size < file_content_size)
	{
		std::cout << "Error in write file content" << std::endl;
		exit(1);
	}

	fclose(file);
	CryptographyManager::unoptimizedMemset(file_content, file_content_size);
}


// TO DO: insert in a utility class
bool ConnectionManager::fileAlreadyExists(std::string filename)
{
    std::ifstream infile(filename);
    return infile.good();
}


std::string ConnectionManager::getRequestCommand()
{
	unsigned char* request_message = nullptr;
	receivePacket(request_message);

	unsigned int plaintext_size;
	unsigned char* plaintext = getMessagePlaintext(request_message, 
													plaintext_size);

	// pointers to first and to last array element
	std::string command(plaintext, 
						plaintext + plaintext_size/sizeof(plaintext[0]));


	free(request_message);
	return command;
}

unsigned char* ConnectionManager::getMessagePlaintext
											(unsigned char* message,
											unsigned int& plaintext_size)
{
	Deserializer deserializer = Deserializer(message);

	unsigned char* plaintext = parseReceivedMessage
												(deserializer, 
												plaintext_size);

	return plaintext;

// TO DO: insert in a utility class
bool ConnectionManager::isFilenameValid(std::string filename) 
{
	return regex_match(filename, regex("^[A-Za-z0-9]*\\.[A-Za-z0-9]+$"));
}

