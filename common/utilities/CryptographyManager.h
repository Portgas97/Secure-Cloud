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
        static const int getNonceSize();
		static EVP_PKEY* getPrivateKey();
        static unsigned char* getPublicKey(EVP_PKEY*, int&);
        static unsigned char* signMessage(unsigned char*, int, const char*, 
                                            unsigned int&);
        static void loadCertificationAuthorityCertificate();

    private:
        const static int NONCE_SIZE = 16;
        
        // TO DO, cannot initialize types other than int in static declarations, must be done in .cpp
        const static char* CERTIFICATION_AUTHORITY_CERTIFICATE_FILENAME =
                            "../files/FoundationsOfCybersecurity_cert.pem"; 
        const static char* CERTIFICATION_AUTHORITY_CRL_FILENAME =
                            "../files/FoundationsOfCybersecurity_crl.pem";
        static X509_STORE* certification_authority_store;
                                    
};

#endif
