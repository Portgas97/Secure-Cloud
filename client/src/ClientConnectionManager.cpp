#include "ClientConnectionManager.h"


ClientConnectionManager::ClientConnectionManager()
{
    createConnection();
    obtainUsername();
}


ClientConnectionManager::~ClientConnectionManager()
{

}


/*
    it initializes the connection socket and performs the actual connection
*/
void ClientConnectionManager::createConnection()
{
    socket_fd = socket(AF_INET, SOCK_STREAM, 0);

    if(socket_fd < 0)
    {
        std::cout << "Error in socket\n";
        exit(1);
    }

    const int yes = 1;
    setsockopt(socket_fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int));

    struct sockaddr_in server_address;

    std::memset(&server_address, 0, sizeof(server_address));
    server_address.sin_family = AF_INET;
    server_address.sin_port = htons(SERVER_PORT);
    inet_pton(AF_INET, SERVER_ADDRESS, &server_address.sin_addr);

    socklen_t address_length = (socklen_t) sizeof(server_address);
    int return_value = connect(socket_fd, (struct sockaddr*)&server_address, 
																address_length);

    if(return_value < 0)
    {
        std::cout << "Error in connect\n";
        exit(1);
    }

}


void ClientConnectionManager::destroyConnection()
{
    // TO DO
}


/*
    it asks the username to the user and assigns it to the relative 
    class attribute
*/
void ClientConnectionManager::obtainUsername()
{
    std::cout << "Insert your username: ";

    // get the input username from the client
    if(fgets(username, MAX_USERNAME_SIZE, stdin) == nullptr)
    {
        std::cout << "Error in fgets\n";
        exit(1);
    }

    // check if username is too long
    if(!strchr(username, '\n'))
    {
        std::cout << "Error: the username you inserted is too long\n";
        exit(1);
    }

    username[strcspn(username, "\n")] = 0;
    std::cout << "username check: " << username << std::endl;

}


/*
    it creates the hello packet and returns it.
    It returns the hello packet size
*/
unsigned int ClientConnectionManager::getHelloPacket(unsigned char* hello_packet)
{
	Serializer serializer = Serializer(hello_packet);

    // hello_packet: username_size | username | nonce_size | nonce
	serializer.serializeInt(strlen(username) + 1);
 	serializer.serializeString(username, strlen(username) + 1);
    std::cout << "int to serialize: " << CryptographyManager::getNonceSize() << std::endl;
    std::cout << "string to serialize: " << client_nonce << std::endl;
	serializer.serializeInt(CryptographyManager::getNonceSize());
	serializer.serializeString(client_nonce, CryptographyManager::getNonceSize());

	return serializer.getOffset();	
}


/*
    it creates the client nonce, the client hello and sends the client
    hello to the server
*/
void ClientConnectionManager::sendHello()
{
	std::cout << "sendHello() init" << std::endl;

	// nonce = (char*)calloc(1, CryptographyManager::getNonceSize());
    // if(nonce == nullptr)
    // {
    //     std::cout << "Error in calloc" << std::endl;
    //     exit(1);
    // }

    CryptographyManager::getNonce(client_nonce);
    // nonce_size = CryptographyManager::getNonceSize();

    // hello_packet: username_size | username | nonce_size | nonce
    unsigned char* hello_packet = (unsigned char*)calloc(1, MAX_HELLO_SIZE);

    if (hello_packet == nullptr) 
    {
        std::cout << "Error in hello packet calloc\n";
        exit(1);
    }

    unsigned int hello_packet_size = getHelloPacket(hello_packet);

    sendPacket(hello_packet, hello_packet_size);

	free(hello_packet);
	std::cout << "sendHello() end" << std::endl;
}



void ClientConnectionManager::receiveHello()
{
    std::cout << "receiveHello() init" << std::endl;

    unsigned char* hello_packet = nullptr;
	receivePacket(hello_packet);

    std::cout << "serverHello received, parsing..." << std::endl;
    Deserializer deserializer = Deserializer(hello_packet);

    // hello packet:
	// nonce_size | nonce | certificate_size | certificate | key_size | key
  	// signature_size | signature

    unsigned int received_nonce_size = deserializer.deserializeInt();

    // char* received_nonce = (char*)calloc(1, received_nonce_size);
    // if(received_nonce == nullptr)
    // {
    //     std::cout << "Error in calloc" << std::endl;
    //     exit(1);
    // }

    if(received_nonce_size != CryptographyManager::getNonceSize())
    {
        std::cout << "Error: received_nonce_size is wrong" << std::endl;
        exit(1);
    }
    deserializer.deserializeString(server_nonce, received_nonce_size);

    std::cout << "received_nonce: " << server_nonce << std::endl;
    std::cout << "received_nonce_size: " << received_nonce_size << std::endl;
    // std::cout << "getNonceSize(): " << CryptographyManager::getNonceSize() << std::endl;            

    unsigned int server_certificate_size = deserializer.deserializeInt();
    std::cout << "server_certificate_size: " << server_certificate_size << std::endl;
    unsigned char* server_certificate = (unsigned char*)calloc(1, 
                                                    server_certificate_size);
    if(server_certificate == nullptr)
    {
        std::cout << "Error in calloc" << std::endl;
        exit(1);
    }

    deserializer.deserializeByteStream(server_certificate, 
                                                    server_certificate_size);
    std::cout << std::endl;
    printBuffer(server_certificate, server_certificate_size);

    X509* deserialized_server_certificate = 
                        CryptographyManager::deserializeData(server_certificate, 
                                                        server_certificate_size);

    CryptographyManager cryptography_manager = CryptographyManager();
    cryptography_manager.verifyCertificate(deserialized_server_certificate);                                                        

    EVP_PKEY* server_public_key =
                         X509_get_pubkey(deserialized_server_certificate);

    unsigned int ephemeral_server_key_size = deserializer.deserializeInt();
    unsigned char* ephemeral_server_key = (unsigned char*)calloc(1, 
                                                    ephemeral_server_key_size);
    if(ephemeral_server_key == nullptr)
    {
        std::cout << "Error in calloc" << std::endl;
        exit(1);
    }
    deserializer.deserializeByteStream(ephemeral_server_key, 
                                                    ephemeral_server_key_size);

    X509* deserialized_ephemeral_server_key =
                    CryptographyManager::deserializeData(ephemeral_server_key,
                                                    ephemeral_server_key_size);

    unsigned int server_signature_size = deserializer.deserializeInt();
    unsigned char* server_signature = (unsigned char*)calloc(1, 
                                                    server_signature_size);
    if(server_signature == nullptr)
    {
        std::cout << "Error in calloc" << std::endl;
        exit(1);
    }
    deserializer.deserializeByteStream(server_signature, 
                                                    server_signature_size);

    unsigned int clear_message_size = ephemeral_server_key_size 
                                    + CryptographyManager::getNonceSize();
    unsigned char *clear_message = (unsigned char*)calloc(1, 
                                                    clear_message_size);
    if(clear_message == nullptr)
    {
        std::cout << "Error in calloc" << std::endl;
        exit(1);
    }

    memcpy(clear_message, ephemeral_server_key, ephemeral_server_key_size);
    memcpy(clear_message + ephemeral_server_key_size, client_nonce, 
                            CryptographyManager::getNonceSize());
        
    cryptography_manager.verifySignature(server_signature, server_signature_size, 
                                        clear_message, clear_message_size, 
                                        server_public_key);

    free(hello_packet);
	std::cout << "receiveHello() end" << std::endl;


}



