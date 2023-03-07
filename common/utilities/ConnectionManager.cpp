#include "ConnectionManager.h"

ConnectionManager::ConnectionManager()
{
        
}

/*
    it receives packet from the sender by receiving first the packet size, then
    the data packet and it returns the received data packet
*/
void ConnectionManager::receivePacket(unsigned char* packet)
{
    uint32_t packet_length;
    int return_value = recv(socket_fd, &packet_length, sizeof(uint32_t), 0);

    if(return_value <= 0)
    {
        std::cout << "Error in recv\n";
        exit(1);
    }

    packet_length = ntohl(packet_length);

    if(return_value < sizeof(uint32_t))
    {
        std::cout << "Received " << return_value << " bytes instead of " 
                    << sizeof(uint32_t) << "\n";
        exit(1);
    }

    // allocate needed memory space for the packet
    packet = (unsigned char*) calloc(1, packet_length);

    if(packet == NULL)
    {
        std::cout << "Error in packet calloc\n";
        exit(1);
    }

    uint32_t received_bytes = 0;

    // hendle fragmented reception
    while(received_bytes < packet_length)
    {
        return_value = recv(socket_fd, (void*)packet, packet_length,  
                                                    MSG_WAITALL);

        if(return_value <= 0)
        {
            std::cout << "Error in recv\n";
            exit(1);
        }

        received_bytes += return_value;
    }
}

/*
    it sends first the packet length, then the packet itself 
*/
void ConnectionManager::sendPacket(unsigned char* packet, 
                                    uint32_t packet_length)
{
    packet_length = htonl(packet_length);

    int return_value = send(socket_fd, &packet_length, sizeof(packet_length), 0);

    if (return_value < 0) 
    {
        std::cout << "Error in send\n";
        exit(1);
    }

    packet_length = ntohl(packet_length);
    uint32_t bytes_sent = 0;

    // handle fragmented send
    while (bytes_sent < packet_length)
    {
        return_value = send(socket_fd, packet + bytes_sent, 
                            packet_length - bytes_sent, 0);
        if (return_value < 0) 
        {
            std::cout << "Error in send\n";
            exit(1);
        }

        bytes_sent += return_value;
    }

    free(packet);
}
