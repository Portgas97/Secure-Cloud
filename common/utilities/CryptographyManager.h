#ifndef CRYPTOGRAPHY_MANAGER_H
#define CRYPTOGRAPHY_MANAGER_H

#include <string>
#include <cstring>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/hmac.h>
#include <openssl/x509.h>
#include <openssl/rand.h>
#include <iostream>

class CryptographyManager
{
    public:
        static void getNonce(char*);
        static int getNonceSize();
		static EVP_PKEY* getPrivateKey();

    private:
        const static int NONCE_SIZE = 8;
};

#endif
