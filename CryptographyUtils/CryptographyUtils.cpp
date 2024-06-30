#include <openssl/bn.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <stdexcept>
#include "CryptographyUtils.h"

DiffieHellmanKeys::DiffieHellmanKeys(const unsigned int& bits) : bits(bits) {
    ctx = BN_CTX_new();
    p = BN_new();
    g = BN_new();
    privateA = BN_new();
    publicA = BN_new();
    secret = BN_new();
    BN_set_word(g, 2); // Set primitive root to 2.
    cryptoKey = new unsigned char[32];
    if (!ctx || !p || !g || !privateA || !publicA || !secret) {
        throw std::runtime_error("Failed to initialize BIGNUMs in DiffieHellmanKeys struct.");
    }
}

DiffieHellmanKeys::~DiffieHellmanKeys() {
    BN_free(p);
    BN_free(g);
    BN_free(privateA);
    BN_free(publicA);
    BN_free(secret);
    BN_CTX_free(ctx);
    delete[] cryptoKey;
}

void DiffieHellmanKeys::generatePrime() {
    if (!BN_generate_prime_ex2(p, bits, 1, NULL, NULL, NULL, ctx)) {
        throw std::runtime_error("failed to generate prime number in DiffieHellmanKeys struct.");
    }
}

void DiffieHellmanKeys::generatePrivate() {
    if (!BN_rand(privateA, bits, BN_RAND_TOP_ONE, BN_RAND_BOTTOM_ANY)) {
        throw std::runtime_error("Failed to generate private key in DiffieHellmanKeys struct.");
    }
}

void DiffieHellmanKeys::generatePublic() {
    if (!BN_mod_exp(publicA, g, privateA, p, ctx)) {
        throw std::runtime_error("Failed to generate a public key in DiffieHellmanKeys struct.");
    }
}

void DiffieHellmanKeys::generateSecret(const char* otherPublicHex) {
    BIGNUM *otherPublic = NULL;
    if (!BN_hex2bn(&otherPublic, otherPublicHex)) {
        throw std::runtime_error("Failed to convert hex to BIGNUM in DiffieHellmanKeys struct.");
    }
    if (!BN_mod_exp(secret, otherPublic, privateA, p, ctx)) {
        BN_free(otherPublic);
        throw std::runtime_error("Failed to generate shared secret in DiffieHellmanKeys struct.");
    }
    BN_free(otherPublic);
}

void DiffieHellmanKeys::setPrime(const char* primeHex) {
    if (!BN_hex2bn(&p, primeHex)) {
        throw std::runtime_error("Failed to set prime number in DiffieHellmanKeys struct.");
    }
}

const char* DiffieHellmanKeys::getPrime() {
    return BN_bn2hex(p);
}

const char* DiffieHellmanKeys::getPublic() {
    return BN_bn2hex(publicA);
}

void DiffieHellmanKeys::generateCryptoKey() {
    if (secret == nullptr || BN_is_zero(secret)) throw std::runtime_error("Secret has not been properly initialized or is zero.");

    int secretLength = BN_num_bytes(secret);
    unsigned char* secretBuffer = new unsigned char[secretLength];
    BN_bn2bin(secret, secretBuffer);

    EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    if (!pctx) {
        delete[] secretBuffer;
        throw std::runtime_error("Failed to create EVP_PKEY_CTX for HKDF");
    }

    EVP_PKEY_derive_init(pctx);
    EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha256());
    EVP_PKEY_CTX_set1_hkdf_salt(pctx, nullptr, 0);
    EVP_PKEY_CTX_set1_hkdf_key(pctx, secretBuffer, secretLength);
    //EVP_PKEY_CTX_add1_hkdf_info(pctx, nullptr, 0);

    size_t keyLen = 32;  // AES-256 key length
    if (EVP_PKEY_derive(pctx, cryptoKey, &keyLen) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        delete[] secretBuffer;
        throw std::runtime_error("Key derivation failed");
    }

    EVP_PKEY_CTX_free(pctx);
    delete[] secretBuffer;
}

const unsigned char* DiffieHellmanKeys::getCryptoKey() {
    return cryptoKey;
}
