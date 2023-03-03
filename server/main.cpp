#include <iostream>
#include "../common/utilities/ServerConnectionManager.cpp"

int main()
{
    ServerConnectionManager serverConnectionManager = ServerConnectionManager();

    

    int client_socket;

    while(1){

        // create the new socket for the connection with a client
        if((client_socket = accept(master_socket, (struct sockaddr *) &client_address, &addr_size)) < 0)
        {
            std::cout << "Error in accept\n";
            exit(1);
        }
                                  
        pid_t child_pid = fork();

        // error
        if(child_pid < 0) 
        {
            std::cout << "Error in fork\n";
            exit(1);
        }

        // child
        if(child_pid == 0)
        {  

            /* 
            // test connection
            if(send(client_socket, "Hello, world!\n", 14, 0) == -1)
                error("send");
            */ 

            return 0;
        } 
        
    }     

        


}