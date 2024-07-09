#ifndef CRYPTOGRAPHY
#define CRYPTOGRAPHY

#include <string>
#include <stdexcept>

#include <openssl/bio.h>    // Base64
#include <openssl/evp.h>    // Base64 // AES
#include <openssl/buffer.h> // Base64
#include <openssl/dh.h>     // Diffie-Hellman
#include <openssl/engine.h> // Diffie-Hellman
#include <openssl/rand.h>   // Diffie-Hellman // AES
#include <openssl/kdf.h>    // Diffie-Hellman // AES

// BASE64

std::string encodeBase64(const std::string &input);
std::string decodeBase64(const std::string &input);

// DIFFIE-HELLMAN

struct DiffieHellman {
private:

    BN_CTX *ctx;
    BIGNUM *p, *g, *privateKey, *publicKey, *secret;
    const unsigned int bits;
    unsigned char *aesKey;

public:

    DiffieHellman(const unsigned int& bits);
    ~DiffieHellman();

    void generatePrime();
    void generatePrivate();
    void generatePublic();
    void generateSecret(const char* otherPublicHex);
    void generateAESKey();
    void setPrime(const char* primeHex);
    const char* getPrime();
    const char* getPublic();
    unsigned char* getAESKey();
    
};

// AES-256 ECB

std::string encryptAES256ECB(std::string& plainText, unsigned char* aesKey);
std::string decryptAES256ECB(std::string& cipherText, unsigned char* aesKey);

#endif // CRYPTOGRAPHY