#include "server.h"

// error printing
void error(const char *msg){
    perror(msg);
    exit(1);
}


int main(int argc, char *argv[]){

    // create the server master socket
    int master_socket;
    if((master_socket = socket(AF_INET, SOCK_STREAM, 0)) < 0)
        error("master_socket instantiation");
    cout << "master_socket opened" << endl;

    // socket options to reuse the same port
    int yes = 1;
    if (setsockopt(master_socket, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1) 
        error("setsockopt"); 

    // declare and clear the structure for the server address
    struct sockaddr_in server_address;
    memset((void*) &server_address, 0, sizeof(server_address));

    // set the parameters for server_address
    server_address.sin_family = AF_INET;
    server_address.sin_addr.s_addr = INADDR_ANY;
    server_address.sin_port = htons(SERVER_PORT); 

    // bind the socket with address and port
    if((bind(master_socket, (struct sockaddr *) &server_address, sizeof(server_address))) < 0)
        error("master_socket binding");
    cout << "master_socket binded" << endl;

    // place incoming connections into a backlog queue
    if((listen(master_socket, BACKLOG_QUEUE)) <0)
        error("master_socket listen");
    cout << "master_socket is listening..." << endl;

    // accept connections
    while(1){
        
        // address length
        socklen_t addr_size;

        // declare and clear the client_address structure
        struct sockaddr_in client_address;
        memset((void*) &client_address, 0, sizeof(client_address));

        // create the new socket for the connection with a client
        int client_socket;
        if((client_socket = accept(master_socket, (struct sockaddr *) &client_address, addr_size)) < 0){
            error("client_socket instantiation");
            continue;
        }
        cout << "connection accepted from: " + inet_ntoa(client_address.sin_addr) + ": " + ntohs(client_address.sin_port_p) << endl;
                
                                  
        pid_t child_pid = fork();

        // error
        if(child_pid < 0) 
            error("fork error");

        // child
        if(child_pid == 0){  
            if(close(master_socket) < 0)
                error("master_socket closure");
            cout << "master_socket closed" << endl;

            if(send(client_socket, "Hello, world!\n", 14, 0) == -1)
                error("send");
            
            close(client_socket);
            exit(0);
            // send and receive
            // ...
            // TODO 
        } 
        
        // parent doesn't need this
        if(close(client_socket) < 0)
            error("master_socket closure");
        cout << "client_socket closed" << endl;
    }     

    return 0;  
}

