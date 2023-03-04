#include <iostream>
#include <unistd.h>
#include <arpa/inet.h>
#include "ServerConnectionManager.h"

ClientConnectionManager::ClientConnectionManager()
{
    createConnection();
}

void ClientConnectionManager::createConnection()
{
    socket = socket(AF_INET, SOCK_STREAM, 0);

    if(socket < 0)
    {
        std::cout << "Error in socket\n";
        exit(1);
    }

    struct sockaddr_in server_address;
    socklen_t address_length;

    memset(&server_address, 0, sizeof(server_address));
    server_address.sin_family = AF_INET;
    server_address.sin_port = htons(SERVER_PORT);
    inet_pton(AF_INET, SERVER_ADDRESS, &server_address.sin_addr);

    address_length = (socklen_t) sizeof(server_address);
    int return_value = connect(socket, (struct sockaddr*)&server_address, address_length);

    if(return_value < 0)
    {
        std::cout << "Error in connect\n";
        exit(1);
    }

}