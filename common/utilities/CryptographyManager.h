#ifndef CRYPTOGRAPHY_MANAGER_H
#define CRYPTOGRAPHY_MANAGER_H

#include <string>
#include <cstring>
#include <iostream>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/conf.h>
#include <openssl/hmac.h>
#include <openssl/x509.h>
#include <openssl/rand.h>


class CryptographyManager
{
    public:
        CryptographyManager();
        ~CryptographyManager();
        static void getNonce(char*);
        static unsigned int getNonceSize();
		static unsigned char* getSharedSecret(EVP_PKEY*, EVP_PKEY*, 
											    size_t*);
	    static EVP_PKEY* getPrivateKey();
        static unsigned char* getSharedKey(unsigned char*, unsigned int);
        static unsigned char* serializeKey(EVP_PKEY*, unsigned int&);
        static EVP_PKEY* deserializeKey(unsigned char*, unsigned int);
        static unsigned char* signMessage(unsigned char*, int, const char*,
                                            unsigned int&);

        static X509* deserializeCertificate(unsigned char*, unsigned int);
        void verifyCertificate(X509*);
        static void verifySignature(unsigned char*, unsigned int, 
								    unsigned char*, unsigned int, EVP_PKEY*);
     
    private:
        
        const char* CERTIFICATION_AUTHORITY_CERTIFICATE_FILENAME =
                            "common/files/FoundationsOfCybersecurity_cert.pem"; 
        const char* CERTIFICATION_AUTHORITY_CRL_FILENAME =
                            "common/files/FoundationsOfCybersecurity_crl.pem";
		
        static const int NONCE_SIZE = 16;
        static const unsigned int SHARED_KEY_SIZE = 32; // bytes

        X509_STORE* certification_authority_store;
        
        void loadCertificationAuthorityCertificate();
		static void unoptimizedMemset(unsigned char*, size_t);
                                    
};

#endif
