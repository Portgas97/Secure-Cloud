#include "server.h"

using namespace std;

// error printing
void error(const char *msg){
    Color::Modifier red(Color::FG_RED);
    Color::Modifier def(Color::FG_DEFAULT);
    cout << red << "! WARNING !" << def << endl;
    perror(msg);
    exit(EXIT_FAILURE);
}


int main(int argc, char *argv[]){

    // colour the terminal output
    Color::Modifier green(Color::FG_GREEN); // green
    Color::Modifier red(Color::FG_RED);     // red
    Color::Modifier def(Color::FG_DEFAULT); // default

    // create the server master socket
    int master_socket;
    if((master_socket = socket(AF_INET, SOCK_STREAM, 0)) == -1)
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
    // parameters
    constexpr int SERVER_PORT = 3490;     // the port users will connect to
    server_address.sin_port = htons(SERVER_PORT); 

    // bind the socket with address and port
    if((bind(master_socket, (struct sockaddr *) &server_address, sizeof(server_address))) < 0)
        error("master_socket binding");
    cout << "master_socket binded" << endl;

    // place incoming connections into a backlog queue
    // SOMAXCONN is defined in sys/socket.h
    if((listen(master_socket, SOMAXCONN)) == -1)
        error("master_socket listen");
    cout << "master_socket is listening..." << endl;

    // accept connections
    while(1){

        // declare and clear the client_address structure
        struct sockaddr_in client_address;
        memset((void*) &client_address, 0, sizeof(client_address));

        // address length
        socklen_t addr_size;
        addr_size = sizeof(struct sockaddr_in);

        // create the new socket for the connection with a client
        int client_socket;
        if((client_socket = accept(master_socket, (struct sockaddr *) &client_address, &addr_size)) == -1){
            error("client_socket instantiation");
            continue;
        }
        string connected_address = inet_ntoa(client_address.sin_addr);
        unsigned connected_port = ntohs(client_address.sin_port);
        cout << "connection accepted from: " + connected_address << ":" << connected_port << endl;
                
                                  
        pid_t child_pid = fork();

        // error
        if(child_pid < 0) 
            error("fork error");

        // child
        if(child_pid == 0){  
            if(close(master_socket) == -1)
                error("master_socket closure");
            cout << "master_socket closed" << endl;

            /* 
            // test connection
            if(send(client_socket, "Hello, world!\n", 14, 0) == -1)
                error("send");
            */ 

            
            // 1) AUTHENTICATION (using public key certificates)
            cout << green << "Authentication is starting..." << def << endl;

            // 2) SYMMETRIC SESSION KEY ESTEBLISHMENT (perfect Forward Secrecy)
            cout << green << "Symmetric Session Key Establishment is starting..." << def << endl;

            // 3) SESSION (encrypted and authenicated)
            cout << green << "Exchange of application data is starting..." << def <<  endl;

            
            if(close(client_socket) == -1)
                error("client_socket closure");
            cout << "client_socket closed" << endl;
            return 0;
        } 
        
        // parent doesn't need this
        if(close(client_socket) == -1)
            error("client_socket closure");
        cout << "client_socket closed" << endl;
    }     

    return 0;  
}

