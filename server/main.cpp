#include <iostream>
#include "../common/utilities/ServerConnectionManager.cpp"

int main()
{
    ServerConnectionManager server_connection_manager = ServerConnectionManager();

    

    int client_socket;

    while(1)
    {
        server_connection_manager.accept();
        
    }     

        


}