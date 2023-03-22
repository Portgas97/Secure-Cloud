#include "ConnectionManager.h"

ConnectionManager::ConnectionManager()
{
        
}

ConnectionManager::~ConnectionManager()
{
    
}

void ConnectionManager::printBuffer(unsigned char* buffer, unsigned int buffer_size)
{
    for(unsigned int i = 0; i < buffer_size; i++)
        std::cout << buffer[i];

    std::cout << std::endl;
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
												const int operation_code)
{
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
													message_counter, aad_size);

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

	return message;
}

