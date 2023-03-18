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
    std::cout << "receivePacket() init" << std::endl;
    uint32_t packet_length;
    int return_value = recv(socket_fd, (void*)&packet_length, sizeof(uint32_t), 0);

    if(return_value <= 0)
    {
        std::cout << "Error in recv" << std::endl;
        exit(1);
    }
    

    packet_length = ntohl(packet_length);

	std::cout << "Received packet length: " << packet_length << std::endl;

    if(return_value < (int)sizeof(uint32_t))
    {
        std::cout << "Received " << return_value << " bytes instead of " 
                    << sizeof(uint32_t) << std::endl;
        exit(1);
    }
    
    //allocate needed memory space for the packet
    unsigned char* received_packet = (unsigned char*) calloc(1, packet_length);
    if(received_packet == nullptr)
    {
        std::cout << "Error in packet calloc" << std::endl;
        exit(1);
    }

    uint32_t received_bytes = 0;


    // hendle fragmented reception
    while(received_bytes < packet_length)
    {
        return_value = recv(socket_fd, (void*)received_packet, packet_length,  
                                                    MSG_WAITALL);

        if(return_value <= 0)
        {
            std::cout << "Error in recv" << std::endl;
            exit(1);
        }

        received_bytes += return_value;
    }

    packet = received_packet;
    // std::cout << "hello_packet received: ";
    // printBuffer(packet, packet_length);

    std::cout << "receivePacket() end." << std::endl;
}

/*
    it sends first the packet length, then the packet itself 
*/
void ConnectionManager::sendPacket(unsigned char* packet, 
                                    uint32_t packet_length)
{
    std::cout << "sendPacket() init, sending " << packet_length << " bytes" << std::endl;
    packet_length = htonl(packet_length);

    int return_value = send(socket_fd, (void*)&packet_length, 
									sizeof(uint32_t), 0);

    if (return_value < 0) 
    {
        std::cout << "Error in send" << std::endl;
        exit(1);
    }

    packet_length = ntohl(packet_length);

    uint32_t bytes_sent = 0;

    // handle fragmented send
    while (bytes_sent < packet_length)
    {
        return_value = send(socket_fd, (void*)(packet + bytes_sent), 
                            packet_length - bytes_sent, 0);

        if (return_value < 0) 
        {
            std::cout << "Error in send" << std::endl;
            exit(1);
        }

        bytes_sent += return_value;
    }

    std::cout << "sendPacket() end" << std::endl;
}
