#include "CryptographyManager.h"

CryptographyManager::CryptographyManager()
{
    loadCertificationAuthorityCertificate();
}

void CryptographyManager::getNonce(char *nonce)
{
    // seed the random generator
    if(RAND_poll() < 0)
    {
        std::cout << "Error in RAND_poll" << std::endl;
        exit(1);
    }

    // create the actual nonce
    if(RAND_bytes((unsigned char*)nonce, NONCE_SIZE) < 0)
    {
        std::cout << "Error in RAND_bytes" << std::endl;
        exit(1);
    }

}


const unsigned int CryptographyManager::getNonceSize()
{
    return NONCE_SIZE;
}


EVP_PKEY* CryptographyManager::getPrivateKey()
{
    EVP_PKEY *parameters = nullptr;
    EVP_PKEY_CTX *context;

    context = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr);

    if (context == nullptr) 
    {
        std::cout << "Error in private key generation" << std::endl;
        exit(1);
    }

    int return_value = EVP_PKEY_paramgen_init(context);
    if (1 != return_value) 
    {
        std::cout << "Error in private key generation" << std::endl;
        exit(1);
    }

    // NID_X9_62_prime256v1 is the used curve
    return_value = EVP_PKEY_CTX_set_ec_paramgen_curve_nid(context, NID_X9_62_prime256v1);
    if (1 != return_value) 
    {
        std::cout << "Error in private key generation" << std::endl;
        exit(1);
    }

    return_value = EVP_PKEY_paramgen(context, &parameters);
    if (1 != return_value) 
    {
        std::cout << "Error in private key generation" << std::endl;
        exit(1);
    }

    // clean the context
    EVP_PKEY_CTX_free(context);

    context = EVP_PKEY_CTX_new(parameters, nullptr);

    EVP_PKEY *private_key = nullptr;

    return_value = EVP_PKEY_keygen_init(context);
    if (1 != return_value) 
    {
        std::cout << "Error in private key generation" << std::endl;
        exit(1);
    }

    return_value = EVP_PKEY_keygen(context, &private_key);
    if (1 != return_value) 
    {
        std::cout << "Error in private key generation" << std::endl;
        exit(1);
    }

    // clean the context and the parameters
    EVP_PKEY_CTX_free(context);
    EVP_PKEY_free(parameters);

    return private_key;
}


unsigned char* CryptographyManager::getPublicKey(EVP_PKEY* private_key, 
                                                unsigned int& public_key_size)
{
	// create new memory bio
    BIO *bio = BIO_new(BIO_s_mem());

	// Serializes a public key (saved in an EVP_PKEY structure) into PEM format
	// and writes it in the BIO.
    int return_value = PEM_write_bio_PUBKEY(bio, private_key);
	if (return_value == 0)
	{
		std::cout << "Error in private key serialization" << std::endl;
        exit(1);
    }

    BUF_MEM *buffer;

	// places the underlying BUF_MEM structure in *buffer
    BIO_get_mem_ptr(bio, &buffer);
    BIO_set_close(bio, BIO_NOCLOSE);

    unsigned char* public_key = (unsigned char *)calloc(1, buffer->length);
    
	if (public_key == nullptr) 
	{
        std::cout << "Error in calloc" << std::endl;
        exit(1);
    }
    memcpy(public_key, buffer->data, buffer->length);

    public_key_size = buffer->length;

    BIO_free(bio);
    return public_key;
}


unsigned char* CryptographyManager::signMessage(unsigned char* message, 
                                            int message_size, 
                                            const char* private_key_filename,
                                            unsigned int& signature_size)
{
    // load private key
    FILE* private_key_file = fopen(private_key_filename, "r");
    if(private_key_file == nullptr)
    {    
        std::cout << "Error in fopen" << std::endl; 
        exit(1); 
    }

    EVP_PKEY* private_key = PEM_read_PrivateKey(private_key_file, 
                                                    nullptr, nullptr, nullptr);
    fclose(private_key_file);

    if(private_key == nullptr)
    { 
        std::cout << "Error in reading private key" << std::endl;
        exit(1); 
    }

    // declare some useful variables
    const EVP_MD* message_digest = EVP_sha256();

    EVP_MD_CTX* signature_context = EVP_MD_CTX_new();
    if(signature_context == nullptr)
    {
        std::cout << "Error in context creation" << std::endl;
        exit(1); 
    }

    // allocate buffer for signature
    unsigned char* signature = (unsigned char*)
                                        calloc(1, EVP_PKEY_size(private_key));
    if(signature == nullptr)
    {
        std::cout << "Error in calloc" << std::endl;
        exit(1); 
    }

    // sign the plaintext: perform a single update on the whole plaintext, 
    // assuming that the plaintext is not huge
    int return_value = EVP_SignInit(signature_context, message_digest);
    if(return_value == 0)
    {
        std::cout << "Error in signature" << std::endl;
        exit(1);
    }

    return_value = EVP_SignUpdate(signature_context, message, message_size);
    if(return_value == 0)
    {
        std::cout << "Error in signature" << std::endl;
        exit(1); 
    }
    
    return_value = EVP_SignFinal(signature_context, signature, &signature_size, private_key);
    if(return_value == 0)
    {
        std::cout << "Error in signature" << std::endl;
        exit(1);
    }

    // delete the digest and the private key from memory
    EVP_MD_CTX_free(signature_context);
    EVP_PKEY_free(private_key);

    return signature;
}     

// TO DO: change name and location?
X509* CryptographyManager::deserializeData(unsigned char* data_buffer, 
                                                unsigned int data_buffer_size)
{
    BIO *bio = BIO_new(BIO_s_mem());
    return_value = BIO_write(bio, data_buffer, data_buffer_size);
    if (return_value == 0) 
    {
        std::cout << "Error in data deserialization" << std::endl;
        exit(1);
    }
    X509 *data = PEM_read_bio_X509(bio, nullptr, nullptr, nullptr);
    if (data == nullptr) 
    {
        cerr << "PEM_read_bio_X509 error";
        exit(1);
    }
    BIO_free(bio);
    return data;
}

void CryptographyManager::verifyCertificate(X509* certificate)
{
    X509_STORE_CTX *context = X509_STORE_CTX_new();
    if (!context) 
    {
        std::cout << "Error in certificate verification" << std::endl;
        exit(1);
    }
    return_value = X509_STORE_CTX_init(context, certification_authority_store, 
                                                        certificate, nullptr);
    if (return_value != 1) 
    {
        std::cout << "Error in certificate verification" << std::endl;
        exit(1);
    }
    return_value = X509_verify_cert(context);

    if(return_value != 1)
    {
        std::cout << "Error: the certificate is not valid" << std::endl;
        exit(1);
    }

    X509_STORE_CTX_free(context);
}

static void CryptographyManager::verifySignature
                                            (unsigned char* signature, 
                                            unsigned int signature_size,
                                            unsigned char* message,
                                            unsigned int message_size,
                                            EVP_PKEY* public_key)
{
    const EVP_MD *message_digest = EVP_sha256();
    EVP_MD_CTX *context = EVP_MD_CTX_new();
    if (context == nullptr) 
    {
        std::cout << "Error in signature verification" << std::endl;
        exit(1);
    }

    int return_value = EVP_VerifyInit(context, message_digest);
    if (return_value == 0)
    {
        std::cout << "Error in signature verification" << std::endl;
        exit(1);
    }


    return_value = EVP_VerifyUpdate(context, message, message_size);
    if (return_value == 0) 
    {
        std::cout << "Error in signature verification" << std::endl;
        exit(1);
    }

    return_value = EVP_VerifyFinal(context, signature, signature_size, 
                                                                    public_key);

    if(return_value == -1 || return_value == 0)
    {
        std::cout << "Error: signature not valid" << std::endl;
        exit(1);
    }

    EVP_MD_CTX_free(context);
}                                            

void CryptographyManager::loadCertificationAuthorityCertificate()
{
    // load the CA's certificate
    FILE* certification_authority_certificate_file = 
                    fopen(CERTIFICATION_AUTHORITY_CERTIFICATE_FILENAME, "r");
    if(certification_authority_certificate_file == nullptr)
    {
        std::cout << "Error in open certificate file" << std::endl;
        exit(1);
    }

    X509* certification_authority_certificate = 
                        PEM_read_X509(certification_authority_certificate_file, 
                                                    nullptr, nullptr, nullptr);
    fclose(certification_authority_certificate_file);
    
    if(certification_authority_certificate == nullptr)
    {
        std::cout << "Error in load certificate" << std::endl;
        exit(1); 
    }

    // load the CRL
    FILE* certification_authority_crl_file = 
                            fopen(CERTIFICATION_AUTHORITY_CRL_FILENAME, "r");
    if(certification_authority_crl_file == nullptr)
    {
        std::cout << "Error in open crl" << std::endl;
        exit(1); 
    }

    X509_CRL* certification_authority_crl = 
                            PEM_read_X509_CRL(certification_authority_crl_file, 
                                                    nullptr, nullptr, nullptr);
    fclose(certification_authority_crl_file);

    if(certification_authority_crl == nullptr)
    {
        std::cout << "Error in load crl" << std::endl;
        exit(1); 
    }

    // build a certification_authority_store with the CA's certificate and
    // the CRL
    certification_authority_store = X509_STORE_new();

    if(certification_authority_store == nullptr)
    {
        std::cout << "Error in storing certification authority" << std::endl;
        exit(1); 
    }

    int return_value = X509_STORE_add_cert(certification_authority_store, 
                                        certification_authority_certificate);
    
    if(return_value != 1)
    {
        std::cout << "Error in storing certification authority" << std::endl;
        exit(1); 
    }

    return_value = X509_STORE_add_crl(certification_authority_store, 
                                                certification_authority_crl);
    if(return_value != 1)
    {
        std::cout << "Error in storing certification authority" << std::endl;
        exit(1); 
    }

    return_value = X509_STORE_set_flags(certification_authority_store, 
                                                        X509_V_FLAG_CRL_CHECK);
    if(return_value != 1)
    {
        std::cout << "Error in storing certification authority" << std::endl;
        exit(1); 
    }

    // TO DO: change location?
    X509_free(certification_authority_certificate);
    X509_CRL_free(certification_authority_crl);
}
                                