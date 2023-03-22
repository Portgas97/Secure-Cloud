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
        static void getRandomBytes(unsigned char*, unsigned int);
        static unsigned int getNonceSize();
		static unsigned int getInitializationVectorSize();
		static unsigned int getTagSize();
		static unsigned char* getSharedSecret(EVP_PKEY*, EVP_PKEY*, 
											size_t*);
		static unsigned char* getSharedKey(unsigned char*, unsigned int);
	    static EVP_PKEY* getPrivateKey();
        static unsigned char* serializeKey(EVP_PKEY*, unsigned int&);
        static X509* deserializeCertificate(unsigned char*, unsigned int);
        static EVP_PKEY* deserializeKey(unsigned char*, unsigned int);
        static unsigned char* signMessage(unsigned char*, int, const char*,
                                         unsigned int&);
        void verifyCertificate(X509*);
        static void verifySignature(unsigned char*, unsigned int, 
									unsigned char*, unsigned int, EVP_PKEY*);
		static unsigned int authenticateAndEncryptMessage(unsigned char*, 
											unsigned int, unsigned char*, 
											unsigned int, unsigned char*,
											unsigned char*, unsigned int,
											unsigned char*, unsigned char*);
		static unsigned int authenticateAndDecryptMessage(unsigned char*, 
											unsigned int, unsigned char*, 
											unsigned int, unsigned char*,
											unsigned char*, unsigned char*,
                                            unsigned int, unsigned char*);
     
    private:
        
        const char* CERTIFICATION_AUTHORITY_CERTIFICATE_FILENAME =
                            "common/files/FoundationsOfCybersecurity_cert.pem"; 
        const char* CERTIFICATION_AUTHORITY_CRL_FILENAME =
                            "common/files/FoundationsOfCybersecurity_crl.pem";
		
        static const unsigned int SHARED_KEY_SIZE = 32; // bytes
        const static unsigned int NONCE_SIZE = 16;
        const static unsigned int INITIALIZATION_VECTOR_SIZE = 12; // TO DO, default is 12, can be set with EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, ivlen, NULL)
		const static unsigned int TAG_SIZE = 16;

        X509_STORE* certification_authority_store;
        
        void loadCertificationAuthorityCertificate();
		static void unoptimizedMemset(unsigned char*, size_t);
                                    
};

#endif
