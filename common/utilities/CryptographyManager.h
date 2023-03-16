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


// TO DO static functions are created when they don't depend on any class members
// or when you don't want to create an instance of an object just to execute
// one public function on it. 
// This is mainly the case for helper classes that contain public functions 
// to do some repetitive and general work, but don't need to maintain 
// any state between calls
// We need an instance because of the first usage? loadCertificationAuthorityCertificate
// depends on class members...

class CryptographyManager
{
    public:
        CryptographyManager();
        static void getNonce(char*);
        static const unsigned int getNonceSize();
		    static EVP_PKEY* getPrivateKey();
        static unsigned char* getPublicKey(EVP_PKEY*, unsigned int&);
        static unsigned char* signMessage(unsigned char*, int, const char*
                                                     unsigned int&);
        static X509* deserializeData(unsigned char*, unsigned int);
        static void verifyCertificate(X509*);
     
    private:
        const static int NONCE_SIZE = 16;
        
        // TO DO, cannot initialize types other than int in static declarations, must be done in .cpp
        const char* CERTIFICATION_AUTHORITY_CERTIFICATE_FILENAME =
                            "../files/FoundationsOfCybersecurity_cert.pem"; 
        const char* CERTIFICATION_AUTHORITY_CRL_FILENAME =
                            "../files/FoundationsOfCybersecurity_crl.pem";
        X509_STORE* certification_authority_store = nullptr;
        
        static void loadCertificationAuthorityCertificate();

                                    
};

#endif
