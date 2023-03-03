#include "client.h"

using namespace std;

// error printing
void error(const char *msg){
    Color::Modifier red(Color::FG_RED);
    Color::Modifier def(Color::FG_DEFAULT);
    cout << red << "! WARNING !" << def << endl;
    perror(msg);
    exit(EXIT_FAILURE);
}


int main(){

    // colour terminal output
    Color::Modifier green(Color::FG_GREEN);
    Color::Modifier red(Color::FG_RED);
    Color::Modifier def(Color::FG_DEFAULT);
    
    // creating the socket
    int socket_fd;
    if((socket_fd = socket(AF_INET, SOCK_STREAM, 0)) == -1)
        error("socket_fd instantiation");
    cout << "socket_fd opened" << endl;

    // setting up the address
    struct sockaddr_in remote_addr;
    memset((void*)&remote_addr, 0, sizeof(remote_addr));
    constexpr int PORT = 3490;     // the port users will connect to
    remote_addr.sin_family = AF_INET;
    remote_addr.sin_port = htons(PORT);
    remote_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    
    // try to connect to the server
    if(connect(socket_fd, (struct sockaddr*) &remote_addr, sizeof(remote_addr)) == -1)
        error("socket connection");
    cout << "client socket connected successfully" << endl;

    // communication
    ssize_t numbytes;
    constexpr int MAX_DATA_SIZE = 1024;
    vector<char> recv_buffer(MAX_DATA_SIZE);
    if((numbytes = recv(socket_fd, recv_buffer.data(), recv_buffer.size() , 0)) == -1)
        error("receiving data");
    recv_buffer.resize(numbytes);
    cout << "data received" << endl;

    // echo
    for(auto i: recv_buffer)
        cout << i;
    cout << endl;

    // 1) AUTHENTICATION (using public key certificates)
    cout << green << "Authentication is starting..." << def << endl;

    // 2) SYMMETRIC SESSION KEY ESTEBLISHMENT (perfect Forward Secrecy)
    cout << green << "Symmetric Session Key Establishment is starting..." << def << endl;

    // 3) SESSION (encrypted and authenicated)
    cout << green << "Exchange of application data is starting..." << def << endl;

    if(close(socket_fd) == -1)
        error("socket_fd closure");
    cout << "socket_fd closed" << endl;

    return 0;
}