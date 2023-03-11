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
        CryptographyManager();
        ~CryptographyManager();
        static void getNonce(char*);
        static int getNonceSize();

    private:
        const static int NONCE_SIZE = 8;
};

#endif
