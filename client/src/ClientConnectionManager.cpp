
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
        std::cout << "Error in socket" << std::endl;
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
        std::cout << "Error in connect" << std::endl;
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
        std::cout << "Error in fgets" << std::endl;
        exit(1);
    }

    // check if username is too long
    if(!strchr(username, '\n'))
    {
        std::cout << "Error: the username you inserted is too long" << std::endl;
        exit(1);
    }

    username[strcspn(username, "\n")] = 0;

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
	serializer.serializeInt(sizeof(nonce));
	serializer.serializeString(nonce, sizeof(nonce));

	return serializer.getOffset();	
}


/*
    it creates the client nonce, the client hello and sends the client
    hello to the server
*/
void ClientConnectionManager::sendHello()
{
	nonce = (char*)calloc(1, CryptographyManager::getNonceSize());
    if(nonce == nullptr)
    {
        std::cout << "Error in calloc" << std::endl;
        exit(1);
    }

    CryptographyManager::getNonce(nonce);

    // hello_packet: username_size | username | nonce_size | nonce
    unsigned char* hello_packet = (unsigned char *) calloc(1, MAX_HELLO_SIZE);

    if (hello_packet == nullptr) 
    {
        std::cout << "Error in hello packet calloc" << std::endl;
        exit(1);
    }

    unsigned int hello_packet_size = getHelloPacket(hello_packet);

    sendPacket(hello_packet, hello_packet_size);
	free(hello_packet);
}



void ClientConnectionManager::receiveHello()
{
    unsigned char* hello_packet = nullptr;
	receivePacket(hello_packet);

    Deserializer deserializer = Deserializer(hello_packet);

    // hello packet:
	// nonce_size | nonce | certificate_size | certificate | key_size | key
  	// signature_size | signature
    unsigned int received_nonce_size = deserializer.deserializeInt();
    unsigned char* received_nonce = nullptr;
    deserializer.deserializeByteStream(received_nonce, received_nonce_size);

    // check if received nonce is different with regard to the send nonce
    int return_value = memcmp(received_nonce, nonce, received_nonce_size);
    if(return_value != 0 || 
                    received_nonce_size != CryptographyManager::getNonceSize())
    {
        std::cout << "Error in hello reception" << std::endl;
        exit(1);
    }                

    unsigned int server_certificate_size = deserializer.deserializeInt();
    unsigned char* server_certificate = nullptr;
    deserializer.deserializeByteStream(server_certificate, 
                                                    server_certificate_size);

    unsigned int ephemeral_server_key_size = deserializer.deserializeInt();
    unsigned char* ephemeral_server_key = nullptr;
    deserializer.deserializeByteStream(ephemeral_server_key, 
                                                    ephemeral_server_key_size);

    unsigned int server_signature_size = deserializer.deserializeInt();
    unsigned char* server_signature = nullptr;
    deserializer.deserializeByteStream(server_signature, 
                                                    server_signature_size);

    // load the CA's certificate
    char* certification_authority_filename = 
                    "../../common/files/FoundationsOfCybersecurity_cert.pem";
    FILE* certification_authority_file = 
                    fopen(certification_authority_filename, "r");

    if(!certification_authority_file)
    {
        std::cout << "Error in open" << std::endl;
        exit(1);
    
    }

    X509* CA_certificate = 
                    PEM_read_X509(certification_authority_file, 
                                    nullptr, nullptr, nullptr);
    
    fclose(certification_authority_file);

    if(CA_certificate == nullptr)
    {
        std::cout << "PEM_read_X509 returned nullptr"; 
        exit(1);
    }

    // load the CRL
    char* crl_filename = 
                "../../common/files/FoundationsOfCybersecurity_crl.pem";
    FILE* crl_file = fopen(crl_filename, "r");

    if(crl_file == nullptr)
    {
        std::cout << "Error in open" << std::endl;
        exit(1);
    }

    X509_CRL* certificate_revocation_list =
                     PEM_read_X509_CRL(crl_file, nullptr, nullptr, nullptr);
    
    fclose(crl_file);

    if(certificate_revocation_list == nullptr)
    {
        std::cout << "PEM_read_X509_CRL returned nullptr";
        exit(1);
    }


    // build a store with the CA's certificate and the CRL
    X509_STORE* store = X509_STORE_new();
    if(store == nullptr)
    { 
        std::cout << "X509_STORE_new returned nullptr" << std::endl;
        exit(1); 
    }

    return_value = X509_STORE_add_cert(store, CA_certificate);
    if(return_value != 1) 
    {
        std::cout << "Error in X509_STORE_add_cert" << std::endl; 
        exit(1);
    }

    return_value = X509_STORE_add_crl(store, certificate_revocation_list);
    if(return_value != 1) 
    { 
        std::cout << "Error in X509_STORE_add_crl" << std::endl;
        exit(1);
    }

    return_value = X509_STORE_set_flags(store, X509_V_FLAG_CRL_CHECK);
    if(return_value != 1) 
    {
        std::cout << "Error in X509_STORE_set_flags" << std::endl; 
        exit(1);
    }

    // load the peer's certificate
    char *certificate_filename[MAX_USERNAME_SIZE + strlen("_cert.pem") + 1];
    memcpy(certificate_filename, username, strlen(username) + 1);
    strncat(certificate_filename, "_cert.pem", strlen("_cert.pem"));

    FILE* certificate_file = fopen(certificate_filename, "r");
    if(!certificate_file)
    {
        std::cout << "Errorin open" << std::endl;
        exit(1); 
    
    }

    X509* certificate = PEM_read_X509(cert_file, nullptr, nullptr, nullptr);
    fclose(certificate_file);

    if(certificate == nullptr)
    {
        std::cout << "PEM_read_X509 returned nullptr" << std::endl;
        exit(1);
    }

    // verify the certificate:
    X509_STORE_CTX* certificate_verify_context = X509_STORE_CTX_new();
    if(certificate_verify_context == nullptr) 
    { 
        std::cout << "X509_STORE_CTX_new returned nullptr" << std::endl;
        exit(1);
    }

    return_value = X509_STORE_CTX_init(certificate_verify_context,
                                        store, certificate, nullptr);
    if(return_value != 1)
    { 
        std::cout << "Error inX509_STORE_CTX_init" << std::endl;
        exit(1);
    }

    return_value = X509_verify_cert(certificate_verify_context);
    if(return_value != 1) 
    { 
        std::cout << "Error in X509_verify_cert" << std::endl;
        exit(1);
    }

    // TO DO, delete after successful executioin
    // print the successful verification to screen:
    char* tmp = X509_NAME_oneline(X509_get_subject_name(certificate), nullptr, 0);
    char* tmp2 = X509_NAME_oneline(X509_get_issuer_name(certificate), nullptr, 0);
    std::cout << "Certificate of \"" << tmp << "\" (released by \"" << tmp2 << "\") verified successfully\n";
    free(tmp);
    free(tmp2);


    // declare some useful variables:
    const EVP_MD* digest_algorithm = EVP_sha256();
    
	// TO DO why the signature is only on key and nonce, and not certificate?

    // read the plaintext from file:
    unsigned char* message = (unsigned char*)calloc(1, 
                                        CryptographyManager::getNonceSize() 
                                        + ephemeral_server_key_size);
    if(message == nullptr)
    {
        std::cout << "Error in malloc" << std::endl;
        exit(1);
    }

    memcpy(message, ephemeral_server_key, ephemeral_server_key_size);

	memcpy(message + ephemeral_server_key_size, 
			received_nonce, 
			CryptographyManager::getNonceSize());

    // create the signature context:
    EVP_MD_CTX* signature_context = EVP_MD_CTX_new();
    if(signature_context == nullptr)
    { 
        std::cout << "EVP_MD_CTX_new returned nullptr" << std::endl; 
        exit(1);
    }

    // verify the plaintext:
    // (perform a single update on the whole plaintext, 
    // assuming that the plaintext is not huge)
    return_value = EVP_VerifyInit(signature_context, digest_algorithm);
    if(return_value == 0)
    { 
        std::cout << "Error in EVP_VerifyInit" << std::endl;
        exit(1);
    }

    return_value = EVP_VerifyUpdate(signature_context, message,
                                        ephemeral_server_key_size 
                                        + CryptographyManager::getNonceSize()); 

    if(return_value == 0)
    {
        std::cout << "Error in EVP_VerifyUpdate" std::endl;
        exit(1);
    }

    return_value = EVP_VerifyFinal( signature_context, 
                                    server_signature, 
                                    server_signature_size, 
                                    X509_get_pubkey(certificate));

    // it is 0 if invalid signature, -1 if some other error, 1 if success.
    if(return_value == -1)
    { 
        std::cout << "Error in EVP_VerifyFinal" << std::endl;
        exit(1);
    }
    else if(return_value == 0)
    {
        std::cout << "Invalid signature!" << std::endl;
        exit(1);
    }

    // print the successful signature verification to screen:
    std::cout << "The Signature has been correctly verified!" << std::endl;

    // deallocate data:
    EVP_MD_CTX_free(signature_context);
    X509_free(certificate);
    X509_STORE_free(store);
    //X509_free(cacert); // already deallocated by X509_STORE_free()
    //X509_CRL_free(crl); // already deallocated by X509_STORE_free()
    X509_STORE_CTX_free(certificate_verify_context);

}



