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
												int operation_code) // TO DO default value also here?
{
	// check counter overflow
 	if(message_counter == UINT32_MAX)
	{
		std::cout << "Error: message counter overflow" << std::endl;
		exit(1);
	}
	
	unsigned int plaintext_size = strlen((char*)plaintext) + 1;
 
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
													message_counter, aad_size, 
													operation_code);

	// packet to be send: AAD | ciphertext | tag
	// AAD: counter | initialization vector
	message_size = 
					// AAD
					sizeof(message_counter)
					+ sizeof(initialization_vector_size) 
					+ initialization_vector_size
					// CT
					+ sizeof(plaintext_size)
					+ plaintext_size
					// TAG
					+ sizeof(CryptographyManager::getTagSize())
					+ CryptographyManager::getTagSize();

	// operation_code is added to the AAD in case of an operation
	if(operation_code != -1)
		message_size += sizeof(operation_code);
	

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
	if(operation_code != -1)
		serializer.serializeInt(operation_code);
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

	return message;
}

// TO DO: maybe the function name is misleading
/*
	It parses received message and check everything is correct, otherwise
	it exits.
*/
void ConnectionManager::parseReceivedMessage(
											Deserializer deserializer,  
											unsigned char*& output_plaintext, 
											unsigned int& output_plaintext_size, 
											int operation_code
											)
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
													message_counter, aad_size, 
													operation_code);

    if(aad == nullptr)
    {
        std::cout << "Error in calloc" << std::endl;
        exit(1);
    }


	unsigned int plaintext_size = 
						CryptographyManager::authenticateAndDecryptMessage
										(ciphertext, ciphertext_size, aad, 
										aad_size, tag, shared_key, 
										initialization_vector, 
                                        initialization_vector_size, plaintext);
	
	output_plaintext = plaintext;
	output_plaintext_size = plaintext_size;

	std::cout << "DBG: received plaintext: ";
	printBuffer(plaintext, plaintext_size);

	free(aad);
    free(tag);
    free(ciphertext);
    free(initialization_vector);

}
