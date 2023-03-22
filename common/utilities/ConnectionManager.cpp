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
