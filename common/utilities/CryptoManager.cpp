#include "CryptoManager.h"

void CryptoManager::getNonce(unsigned char* nonce)
{
    // seed the random generator
    if(RAND_poll() < 0)
    {
        std::cout << "Error in RAND_poll\n";
        exit(1);
    }

    // create the actual nonce
    if(RAND_bytes(nonce, NONCE_SIZE) < 0)
    {
        std::cout << "Error in RAND_bytes\n";
        exit(1);
    }
}

int CryptoManager::getNonceSize()
{
    return NONCE_SIZE;
}