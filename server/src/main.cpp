#include <iostream>
#include "ServerConnectionManager.h"

int main()
{
    ServerConnectionManager server_connection_manager = 
													ServerConnectionManager();
    
    while(1)
        server_connection_manager.acceptRequest();

    return 0;        
}
