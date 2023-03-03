#include <iostream>
#include <unistd.h>
#include "ServerConnectionManager.h"

ServerConnectionManager::ServerConnectionManager()
{
    createConnection();
}

ServerConnectionManager::createConnection()
{
    // declare and clear the client_address structure
    struct sockaddr_in client_address;
    memset((void*) &client_address, 0, sizeof(client_address));

    // address length
    socklen_t addr_size;
    addr_size = sizeof(struct sockaddr_in);

    
    int master_socket = -1;
    while(master_socket < 0)
        master_socket = socket(AF_INET, SOCK_STREAM, 0);

    const int yes = 1;
    setsockopt(master_socket, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int));

    struct sockaddr_in server_address;
    memset(&server_address, 0, sizeof(server_address));

    // set the parameters for server_address
    server_address.sin_family = AF_INET;
    server_address.sin_addr.s_addr = inet_addr();
    
    server_address.sin_port = htons(SERVER_PORT); 

    if((bind(master_socket, (struct sockaddr *) &server_address, sizeof(server_address))) < 0)
    {
        std::cout << "Error in bind\n";
        exit(1);
    }

    if((listen(master_socket, MAX_CONNECTIONS)) < 0)
    {
        std::cout << "Error in listen\n";
        exit(1);
    }

}