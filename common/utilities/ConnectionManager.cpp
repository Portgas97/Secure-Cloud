#include "ConnectionManager.h"
#include <iostream>
#include <sys/socket.h>
#include <arpa/inet.h>

ConnectionManager::ConnectionManager()
{
        
}

/*
    it receives packet from the sender by receiving first the packet size, then
    the data packet and it returns the received data packet
*/
void ConnectionManager::receivePacket(int client_socket, char* buffer)
{
    uint32_t packet_length;
    int return_value = recv(socket, (void*)&packet_length, sizeof(uint32_t), 0);

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

    return_value = recv(client_socket, (void*)buffer, packet_length,  MSG_WAITALL);

    if(return_value <= 0)
    {
        std::cout << "Error in recv\n";
        exit(1);
    }

    if(return_value < packet_length)
    {
        std::cout << "Received " << return_value << " bytes instead of " 
                    << packet_length << "\n";        
        exit(1);
    }

    buffer[packet_length] = '\0';
}