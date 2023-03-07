#include <iostream>
#include "../common/utilities/ServerConnectionManager.h"

int main()
{
    ServerConnectionManager server_connection_manager = ServerConnectionManager();

    

    int client_socket;

    while(1)
    {
        server_connection_manager.acceptRequest();
        
    }     

        


}
