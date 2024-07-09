#include "cryptography.hpp"

/* =============================================================================================================================================================== */
/* = BASE64 ====================================================================================================================================================== */

std::string encodeBase64(const std::string &input) {

    BIO *bio, *b64;
    BUF_MEM *bufferPtr;

    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new(BIO_s_mem());
    bio = BIO_push(b64, bio);

    // Write the input to the BIO
    BIO_write(bio, input.c_str(), input.length());
    BIO_flush(bio);

    // Get the result from the BIO
    BIO_get_mem_ptr(bio, &bufferPtr);
    std::string output(bufferPtr->data, bufferPtr->length);

    // Free the BIOs
    BIO_free_all(bio);

    return output;

}

std::string decodeBase64(const std::string &input) {
    
    BIO *bio, *b64;
    char buffer[input.length()];
    memset(buffer, 0, input.length());

    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new_mem_buf(input.c_str(), input.length());
    bio = BIO_push(b64, bio);

    // Write the decoded data to the buffer
    int decoded_length = BIO_read(bio, buffer, input.length());

    // Free the BIOs
    BIO_free_all(bio);

    return std::string(buffer, decoded_length);

}

/* =============================================================================================================================================================== */
/* = DIFFIE HELLMAN ============================================================================================================================================== */

// CONSTRUCTOR
DiffieHellman::DiffieHellman(const unsigned int& bits) : bits(bits) {

    ctx = BN_CTX_new();
    p = BN_new();
    g = BN_new();
    privateKey = BN_new();
    publicKey = BN_new();
    secret = BN_new();
    BN_set_word(g, 2);
    if (!ctx || !p || !g || !privateKey || !publicKey || !secret) throw std::runtime_error("Failed to initialize BIGNUMs in DiffieHellman struct.");
    aesKey = new unsigned char[32];

}

// DESTRUCTOR
DiffieHellman::~DiffieHellman() {

    BN_free(p);
    BN_free(g);
    BN_free(privateKey);
    BN_free(publicKey);
    BN_free(secret);
    BN_CTX_free(ctx);
    delete[] aesKey;

}

// GENERATORS
void DiffieHellman::generatePrime() {
    if (!BN_generate_prime_ex2(p, bits, 1, NULL, NULL, NULL, ctx)) throw std::runtime_error("failed to generate prime number in DiffieHellman struct.");
}

void DiffieHellman::generatePrivate() {
    if (!BN_rand(privateKey, bits, BN_RAND_TOP_ONE, BN_RAND_BOTTOM_ANY)) throw std::runtime_error("Failed to generate private key in DiffieHellman struct.");
}

void DiffieHellman::generatePublic() {
    if (!BN_mod_exp(publicKey, g, privateKey, p, ctx)) throw std::runtime_error("Failed to generate a public key in DiffieHellman struct.");
}

void DiffieHellman::generateSecret(const char* otherPublicHex) {

    BIGNUM *otherPublic = NULL;

    if (!BN_hex2bn(&otherPublic, otherPublicHex)) throw std::runtime_error("Failed to convert hex to BIGNUM in DiffieHellman struct.");

    if (!BN_mod_exp(secret, otherPublic, privateKey, p, ctx)) {
        BN_free(otherPublic);
        throw std::runtime_error("Failed to generate shared secret in DiffieHellman struct.");
    }

    BN_free(otherPublic);

}

void DiffieHellman::generateAESKey() {

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

    size_t keyLen = 32;  // AES-256 key length
    if (EVP_PKEY_derive(pctx, aesKey, &keyLen) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        delete[] secretBuffer;
        throw std::runtime_error("Key derivation failed");
    }

    EVP_PKEY_CTX_free(pctx);
    delete[] secretBuffer;

}

// SETTERS
void DiffieHellman::setPrime(const char* primeHex) {
    if (!BN_hex2bn(&p, primeHex)) throw std::runtime_error("Failed to set prime number in DiffieHellmanKeys struct.");
}

// GETTERS
const char* DiffieHellman::getPrime() {
    return BN_bn2hex(p);
}

const char* DiffieHellman::getPublic() {
    return BN_bn2hex(publicKey);
}

unsigned char* DiffieHellman::getAESKey() {
    return aesKey;
}

/* =============================================================================================================================================================== */
/* = AES-256 ECB ================================================================================================================================================= */

std::string encryptAES256ECB(std::string& plainText, unsigned char* aesKey) {

    size_t blockSize = 16;
    size_t paddingLength = blockSize - (plainText.size() % blockSize);
    plainText.append(paddingLength, static_cast<char>(paddingLength));

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) throw std::runtime_error("Failed to create context in encrypt function");

    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_ecb(), nullptr, aesKey, nullptr)) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Failed to initialize encryption");
    }

    int outlen1;
    std::string cipherText(plainText.size() + EVP_CIPHER_block_size(EVP_aes_256_ecb()), '\0');

    if (1 != EVP_EncryptUpdate(ctx, reinterpret_cast<unsigned char*>(&cipherText[0]), &outlen1, reinterpret_cast<const unsigned char*>(plainText.c_str()), plainText.size())) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Encryption failed");
    }

    int outlen2;
    if (1 != EVP_EncryptFinal_ex(ctx, reinterpret_cast<unsigned char*>(&cipherText[0]) + outlen1, &outlen2)) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Final encryption step failed");
    }

    EVP_CIPHER_CTX_free(ctx);

    cipherText.resize(outlen1 + outlen2);
    return cipherText;

}

std::string decryptAES256ECB(std::string& cipherText, unsigned char* aesKey) {

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) throw std::runtime_error("Failed to create context in decrypt function");

    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_ecb(), nullptr, aesKey, nullptr)) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Failed to initialize decryption");
    }

    int outLength1, outLength2;
    std::string plainText(cipherText.size(), '\0');

    if (1 != EVP_DecryptUpdate(ctx, reinterpret_cast<unsigned char*>(&plainText[0]), &outLength1, reinterpret_cast<const unsigned char*>(cipherText.c_str()), cipherText.size())) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Decryption failed");
    }

    if (1 != EVP_DecryptFinal_ex(ctx, reinterpret_cast<unsigned char*>(&plainText[0]) + outLength1, &outLength2)) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Final decryption step failed");
    }

    EVP_CIPHER_CTX_free(ctx);

    plainText.resize(outLength1 + outLength2);
    size_t paddingLength = static_cast<size_t>(plainText[plainText.size() - 1]);
    plainText.resize(plainText.size() - paddingLength);

    return plainText;

}

