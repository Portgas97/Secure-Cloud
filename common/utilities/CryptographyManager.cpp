#include "CryptographyManager.h"
#include "ConnectionManager.h"

CryptographyManager::CryptographyManager()
{
    loadCertificationAuthorityCertificate();
}

CryptographyManager::~CryptographyManager()
{
    free(certification_authority_store);
}


void CryptographyManager::getRandomBytes(unsigned char *bytes, 
											unsigned int size)
{
    // seed the random generator
	int return_value = RAND_poll();
    if(return_value < 0)
    {
        std::cout << "Error in RAND_poll" << std::endl;
        exit(1);
    }

    // create the actual bytes
	return_value = RAND_bytes(bytes, size);
    if(return_value < 0)
    {
        std::cout << "Error in RAND_bytes" << std::endl;
        exit(1);
    }
}


unsigned int CryptographyManager::getNonceSize()
{
    return NONCE_SIZE;
}

unsigned int CryptographyManager::getInitializationVectorSize()
{
	return INITIALIZATION_VECTOR_SIZE;
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


unsigned char* CryptographyManager::serializeKey(EVP_PKEY* private_key, 
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

    // delete the message_digest_buffer and the private key from memory
    EVP_MD_CTX_free(signature_context);
    EVP_PKEY_free(private_key);

    return signature;
}     

// TO DO: change name and location?
X509* CryptographyManager::deserializeCertificate(unsigned char* certificate, 
                                                unsigned int certificate_size)
{
    BIO *bio = BIO_new(BIO_s_mem());
    int return_value = BIO_write(bio, certificate, certificate_size);
    if (return_value == 0) 
    {
        std::cout << "Error in data deserialization" << std::endl;
        exit(1);
    }
	X509* deserialized_certificate = PEM_read_bio_X509(bio, nullptr, nullptr, 
																	nullptr);
    if (deserialized_certificate == nullptr) 
    {
		std::cout << "Error in data deserialization" << std::endl;
        exit(1);
    }
    BIO_free(bio);
    return deserialized_certificate;
}

EVP_PKEY* CryptographyManager::deserializeKey(unsigned char* key, 
                                                unsigned int key_size)
{
    BIO *bio = BIO_new(BIO_s_mem());
    int return_value = BIO_write(bio, key, key_size);
    if (return_value == 0) 
    {
        std::cout << "Error in data deserialization" << std::endl;
        exit(1);
    }

	EVP_PKEY* deserialized_key = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, 
																	nullptr);
    if (deserialized_key == nullptr) 
    {
		std::cout << "Error in data deserialization" << std::endl;
        exit(1);
    }
    BIO_free(bio);
    return deserialized_key;
}

void CryptographyManager::verifyCertificate(X509* certificate)
{
    X509_STORE_CTX *context = X509_STORE_CTX_new();
    if (context == nullptr) 
    {
        std::cout << "Error in certificate verification" << std::endl;
        exit(1);
    }
    
    int return_value = X509_STORE_CTX_init(context, 
											certification_authority_store,
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

void CryptographyManager::verifySignature   (unsigned char* signature, 
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
		std::cout << "return_value: " << return_value << std::endl;
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
        std::cout << "Error in storing certification authority certificate" 
        << std::endl;
        exit(1); 
    }

    int return_value = X509_STORE_add_cert(certification_authority_store, 
                                        certification_authority_certificate);
    
    if(return_value != 1)
    {
        std::cout << "Error in storing certification authority certificate" << std::endl;
        exit(1); 
    }

    return_value = X509_STORE_add_crl(certification_authority_store, 
                                                certification_authority_crl);
    if(return_value != 1)
    {
        std::cout << "Error in storing certification authority certificate" << std::endl;
        exit(1); 
    }

    return_value = X509_STORE_set_flags(certification_authority_store, 
                                                        X509_V_FLAG_CRL_CHECK);
    if(return_value != 1)
    {
        std::cout << "Error in storing certification authority certificate" << std::endl;
        exit(1); 
    }

    // TO DO: change location?
    X509_free(certification_authority_certificate);
    X509_CRL_free(certification_authority_crl);
}
 
unsigned char* CryptographyManager::getSharedSecret(EVP_PKEY* private_key,
												EVP_PKEY* public_key,
												size_t* shared_secret_size)
{
    EVP_PKEY_CTX *context = EVP_PKEY_CTX_new(private_key, nullptr);

    // initializes a context for Diffie-Hellman secret derivation
	int return_value = EVP_PKEY_derive_init(context);
    if (return_value != 1) 
	{
		std::cout << "Error in shared secret derivation" << std::endl;
		exit(1);
    }

    // set's the peer's public key
	return_value = EVP_PKEY_derive_set_peer(context, public_key);
    if (return_value != 1) 
	{
		std::cout << "Error in shared secret derivation" << std::endl;
		exit(1);
    }

    unsigned char *shared_secret = nullptr;
	size_t local_shared_secret_size;

    // the first time this API returns the maximum number of bytes needed 
	return_value = EVP_PKEY_derive(context, nullptr, &local_shared_secret_size);
    if (return_value != 1) 
	{
		std::cout << "Error in shared secret derivation" << std::endl;
		exit(1);
    }

    shared_secret = (unsigned char *) calloc(1, local_shared_secret_size);
    if (shared_secret == nullptr) 
	{
		std::cout << "Error in calloc" << std::endl;
		exit(1);
    }

    // the second times derives the shared secret and returns its size
	return_value = EVP_PKEY_derive(context, shared_secret, 
													&local_shared_secret_size);
    if (return_value != 1) 
	{
		std::cout << "Error in shared secret derivation" << std::endl;
		exit(1);
    }

    EVP_PKEY_CTX_free(context);
    EVP_PKEY_free(private_key);

	*shared_secret_size = local_shared_secret_size;

    return shared_secret;
}

unsigned char* CryptographyManager::getSharedKey(unsigned char *shared_secret, 
												unsigned int shared_secret_size) 
{

    const EVP_MD *message_digest = EVP_sha256();

    unsigned char* message_digest_buffer = (unsigned char *) calloc(1, 
												EVP_MD_size(message_digest));
    if (message_digest_buffer == nullptr) 
	{
		std :: cout << "Error in calloc" << std::endl;
		exit(1);
    }

    EVP_MD_CTX *context = EVP_MD_CTX_new();
	int return_value = EVP_DigestInit(context, message_digest);
    if (return_value != 1) 
	{
		std::cout << "Error in shared key derivation" << std::endl;
		exit(1);
    }

	return_value = EVP_DigestUpdate(context, (unsigned char*)shared_secret, 
									shared_secret_size);
    if (return_value != 1) 
	{
		std::cout << "Error in shared key derivation" << std::endl;
		exit(1);
    }

    unsigned int message_digest_buffer_size;
	return_value = EVP_DigestFinal(context, 
									(unsigned char*)message_digest_buffer, 
									&message_digest_buffer_size);
    if (return_value != 1) 
	{
		std::cout << "Error in shared key derivation" << std::endl;
		exit(1);
    }
    
    EVP_MD_CTX_free(context);

    // clean up the shared secret
	unoptimizedMemset(shared_secret, shared_secret_size);
    free(shared_secret);
    
    unsigned char* shared_key = (unsigned char *) calloc(1, SHARED_KEY_SIZE);
    if (shared_key == nullptr) 
	{
		std :: cout << "Error in calloc" << std::endl;
		exit(1);
    }

    memcpy(shared_key, message_digest_buffer, SHARED_KEY_SIZE);

    // clean up message_digest_buffer
	unoptimizedMemset(message_digest_buffer, EVP_MD_size(message_digest));
    free(message_digest_buffer);

    return shared_key;
}

unsigned int CryptographyManager::authenticateAndEncryptMessage 
								(unsigned char *plaintext, 
								unsigned int plaintext_size,
								unsigned char *aad, 
								unsigned int aad_size,
								unsigned char *key,
								unsigned char *initialization_vector, 
								unsigned int initialization_vector_size,
								unsigned char *ciphertext,
								unsigned char *tag)
{

    EVP_CIPHER_CTX *context = EVP_CIPHER_CTX_new(); 
    // Create and initialise the context
    if(context == nullptr)
	{
		std::cout << "Error in authenticate and encrypt message" << std::endl;
		exit(1);
	}

    // Initialise the encryption operation
	int return_value = EVP_EncryptInit(context, EVP_aes_128_gcm(), key, 
										initialization_vector);
    if(return_value != 1)
	{
		std::cout << "Error in authenticate and encrypt message" << std::endl;
		exit(1);
	}

    int size = 0;
    // Provide any AAD data. This can be called zero or more times as required
	return_value = EVP_EncryptUpdate(context, NULL, &size, aad, aad_size);
    if(return_value != 1)
	{
		std::cout << "Error in authenticate and encrypt message" << std::endl;
		exit(1);
	}

	return_value = EVP_EncryptUpdate(context, ciphertext, &size, plaintext, 
									plaintext_size);
    if(return_value != 1)
	{
		std::cout << "Error in authenticate and encrypt message" << std::endl;
		exit(1);
	}
 
    int ciphertext_size = 0;
    ciphertext_size = size;

	//Finalize Encryption
	return_value = EVP_EncryptFinal(context, ciphertext + size, &size);
    if(return_value != 1)
	{
		std::cout << "Error in authenticate and encrypt message" << std::endl;
		exit(1);
	}

    ciphertext_size += size;
    // Get the tag
	return_value = EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_AEAD_GET_TAG, 16, tag);
    if(return_value != 1)
	{
		std::cout << "Error in authenticate and encrypt message" << std::endl;
		exit(1);
	}

    // clean up
    EVP_CIPHER_CTX_free(context);
    return ciphertext_size;
}

unsigned int CryptographyManager::authenticateAndDecryptMessage
										(unsigned char *ciphertext, 
										unsigned int ciphertext_size,
										unsigned char *aad, 
										unsigned int aad_size,
										unsigned char *tag,
										unsigned char *key,
										unsigned char *initialization_vector, 
										unsigned int initialization_vector_size,
										unsigned char *plaintext)
{
    // Create and initialise the context
    EVP_CIPHER_CTX *context = EVP_CIPHER_CTX_new();
    if(context == nullptr)
	{
		std::cout << "Error in authenticate and decrypt message" << std::endl;
		exit(1);
	}
	
	int return_value = EVP_DecryptInit(context, EVP_aes_128_gcm(), key, 
										initialization_vector);
    if(return_value != 1)
	{
		std::cout << "Error in authenticate and decrypt message" << std::endl;
		exit(1);
	}

	int size;
	//Provide any AAD data
	return_value = EVP_DecryptUpdate(context, nullptr, &size, aad, aad_size);
    if(return_value != 1)
	{
		std::cout << "Error in authenticate and decrypt message" << std::endl;
		exit(1);
	}

	//Provide the message to be decrypted, and obtain the plaintext output
	return_value = EVP_DecryptUpdate(context, plaintext, &size, ciphertext, 
									ciphertext_size);
    if(return_value != 1)
	{
		std::cout << "Error in authenticate and decrypt message" << std::endl;
		exit(1);
	}

    unsigned int plaintext_size = size;
    // Set expected tag value
	return_value = EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_AEAD_SET_TAG, 16, tag);
    if(return_value != 1)
	{
		std::cout << "Error in authenticate and decrypt message" << std::endl;
		exit(1);
	}
    
    //Finalise the decryption. A positive return value indicates success,
    // anything else is a failure - the plaintext is not trustworthy.
    return_value = EVP_DecryptFinal(context, plaintext + size, &size);

    // Clean up
    EVP_CIPHER_CTX_cleanup(context);

    if(return_value > 0) // Success
	{
        plaintext_size += size;
        return plaintext_size;
    } else
        return -1;
}


unsigned int CryptographyManager::getTagSize()
{
	return TAG_SIZE;
}


#pragma GCC push_options
#pragma GCC optimize("O0")
void CryptographyManager::unoptimizedMemset(unsigned char* memory_buffer, 
						size_t memory_buffer_size)
{
	memset(memory_buffer, 0, memory_buffer_size);
}
#pragma GCC pop_options                           
