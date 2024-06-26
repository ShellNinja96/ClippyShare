#ifndef cryptography_utils_h 
#define cryptography_utils_h 

#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>


struct DiffieHellmanKeys {
private:
    BN_CTX *ctx;
    BIGNUM *p, *g, *privateA, *publicA, *secret;
    const unsigned int bits;
    unsigned char* cryptoKey;

public:
    DiffieHellmanKeys(const unsigned int& bits);
    ~DiffieHellmanKeys();

    void generatePrime();
    void generatePrivate();
    void generatePublic();
    void generateSecret(const char* otherPublicHex);
    void generateCryptoKey();
    void setPrime(const char* primeHex);
    const char* getPrime();
    const char* getPublic();
    const unsigned char* getCryptoKey();
};

/*
const char* EncodeBase64(const char* input);
const char* DecodeBase64(const char* input);
*/

unsigned char* EncodeBase64(const unsigned char* input);
unsigned char* DecodeBase64(const unsigned char* input);


#endif // cryptography_utils_h 
