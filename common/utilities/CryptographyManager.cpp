#include "CryptographyManager.h"

void CryptographyManager::getNonce(char *nonce)
{
    // seed the random generator
    if(RAND_poll() < 0)
    {
        std::cout << "Error in RAND_poll\n";
        exit(1);
    }

    // create the actual nonce
    if(RAND_bytes((unsigned char*)nonce, NONCE_SIZE) < 0)
    {
        std::cout << "Error in RAND_bytes\n";
        exit(1);
    }

}

int CryptographyManager::getNonceSize()
{
    return NONCE_SIZE;
}

EVP_PKEY CryptographyManager::getPrivateKey()
{
	// parameters generation
    EVP_PKEY* parameters = EVP_PKEY_new();
    if(parameters == nullptr) 
	{
		std::cout << "Error in private key creation" << std::endl;
		exit(1);
    }

    DH* low_parameters = DH_get_2048_224();
    if(EVP_PKEY_set1_DH(parameters, low_parameters) == nullptr) 
	{
		std::cout << "Error in private key creation" << std::endl;
        DH_free(low_parameters);
        EVP_PKEY_free(parameters);
		exit(1);
    }
    DH_free(low_parameters);

	// context generation
    EVP_PKEY_CTX* context = EVP_PKEY_CTX_new(parameters,nullptr);
    if(context == nullptr)
	{
		std::cout << "Error in private key creation" << std::endl;
        EVP_PKEY_free(parameters);
		exit(1);
    }

	// private key generation
    EVP_PKEY* private_key = nullptr;
    if(EVP_PKEY_keygen_init(context) == nullptr)
	{
        EVP_PKEY_free(parameters);
        EVP_PKEY_CTX_free(context);
		std::cout << "Error in private key creation" << std::endl;
		exit(1);
    }
    if(EVP_PKEY_keygen(context,&private_key) == nullptr)
	{
        EVP_PKEY_free(parameters);
        EVP_PKEY_CTX_free(context);
		std::cout << "Error in private key creation" << std::endl;
        exit(1);
    }
    EVP_PKEY_CTX_free(context);
    EVP_PKEY_free(parameters);

    return private_key;
}
