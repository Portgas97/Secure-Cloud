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
        static void getNonce(char*);
        static unsigned int getNonceSize();
		static unsigned char* getSharedKey(EVP_PKEY*, EVP_PKEY*, unsigned int&);
	    static EVP_PKEY* getPrivateKey();
        static unsigned char* serializeKey(EVP_PKEY*, unsigned int&);
        static X509* deserializeCertificate(unsigned char*, unsigned int);
        static EVP_PKEY* deserializeKey(unsigned char*, unsigned int);
        static unsigned char* signMessage(unsigned char*, int, const char*,
                                                     unsigned int&);
        void verifyCertificate(X509*);
        void verifySignature(unsigned char*, unsigned int, unsigned char*,
                                 unsigned int, EVP_PKEY*);
     
    private:
        const static int NONCE_SIZE = 16;
        
        const char* CERTIFICATION_AUTHORITY_CERTIFICATE_FILENAME =
                            "common/files/FoundationsOfCybersecurity_cert.pem"; 
        const char* CERTIFICATION_AUTHORITY_CRL_FILENAME =
                            "common/files/FoundationsOfCybersecurity_crl.pem";
        X509_STORE* certification_authority_store = nullptr;
        
        void loadCertificationAuthorityCertificate();

                                    
};

#endif
