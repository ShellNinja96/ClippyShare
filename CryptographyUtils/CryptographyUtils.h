#ifndef cryptography_utils_h 
#define cryptography_utils_h 

#include <openssl/bn.h>
struct DiffieHellmanKeys {
private:
    BN_CTX *ctx;
    BIGNUM *p, *g, *privateA, *publicA, *secret;
    const unsigned int bits;

public:
    DiffieHellmanKeys(const unsigned int& bits);
    ~DiffieHellmanKeys();

    void generatePrime();
    void generatePrivate();
    void generatePublic();
    void generateSecret(const char* otherPublicHex);
    void setPrime(const char* primeHex);
    const char* getPrime();
    const char* getPublic();
};


#endif // cryptography_utils_h 

