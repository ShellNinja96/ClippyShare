#include <openssl/bn.h>
#include <openssl/rand.h>
#include <iostream>
#include <stdexcept>

struct DiffieHellmanKeys {
public:

    BN_CTX *ctx;
    BIGNUM *p, *g, *privateA, *publicA, *secret;
    const unsigned int bits;

    DiffieHellmanKeys(const unsigned int& bits) : bits(bits) {

        ctx = BN_CTX_new();
        p = BN_new();
        g = BN_new();
        privateA = BN_new();
        publicA = BN_new();
        secret = BN_new();
        BN_set_word(g, 2); // Set primitive root to 2.
        if (!ctx || !p || !g || !privateA || !publicA || !secret) throw std::runtime_error("Failed to initialize BIGNUMs in DiffieHellmanKeys struct.");

    }

    ~DiffieHellmanKeys() {
        BN_free(p);
        BN_free(g);
        BN_free(privateA);
        BN_free(publicA);
        BN_free(secret);
        BN_CTX_free(ctx);
    }

    void generatePrime() {
        if (!BN_generate_prime_ex2(p, bits, 1, NULL, NULL, NULL, ctx)) throw std::runtime_error("failed to generate prime number in DiffieHellmanKeys struct.");
    }

    void generatePrivate() {
        if (!BN_rand(privateA, bits, BN_RAND_TOP_ONE, BN_RAND_BOTTOM_ANY)) throw std::runtime_error("Failed to generate private key in DiffieHellmanKeys struct.");
    }

    void generatePublic() {
        if (!BN_mod_exp(publicA, g, privateA, p, ctx)) throw std::runtime_error("Failed to generate a public key in DiffieHellmanKeys struct.");
    }

    void generateSecret(const char* otherPublicHex) {

        BIGNUM *otherPublic = NULL;

        if (!BN_hex2bn(&otherPublic, otherPublicHex)) throw std::runtime_error("Failed to convert hex to BIGNUM in DiffieHellmanKeys struct.");

        if (!BN_mod_exp(secret, otherPublic, privateA, p, ctx)) {
            BN_free(otherPublic);
            throw std::runtime_error("Failed to generate shared secret in DiffieHellmanKeys struct.");
        }

        BN_free(otherPublic);
    }

    void setPrime(const char* primeHex) {
        if (!BN_hex2bn(&p, primeHex)) throw std::runtime_error("Failed to set prime number in DiffieHellmanKeys struct.");
    }

    const char* getPrime() {
        return BN_bn2hex(p);
    }

    const char* getPublic() {
        return BN_bn2hex(publicA);
    }




};


void print_bn(const char* name, BIGNUM *bn) {
    char *str = BN_bn2dec(bn);
    std::cout << name << ": " << str << std::endl;
    OPENSSL_free(str);
}

int main() {
    
    std::cout << "Initializing Server and Client DH structs\n";
    DiffieHellmanKeys server(1024), client(1024);

    std::cout << "Generating Server prime\n";
    server.generatePrime();

    std::cout << "Setting Client prime\n";
    client.setPrime(server.getPrime());

    std::cout << "Generating Server private\n";
    server.generatePrivate();

    std::cout << "Generating Server public\n";
    server.generatePublic();

    std::cout << "Generating Client private\n";
    client.generatePrivate();

    std::cout << "Generating Client public\n";
    client.generatePublic();

    std::cout << "Generating Server secret\n";
    client.generateSecret(server.getPublic());

    std::cout << "Generating Client secret\n";
    server.generateSecret(client.getPublic());

    print_bn("Server Prime (p)", server.p);
    print_bn("Client Prime (p)", client.p);
    std::cout << std::endl;

    print_bn("Server Root Primitive (g)", server.g);
    print_bn("Client Root Primitive (g)", client.g);
    std::cout << std::endl;

    print_bn("Server Private Key (private)", server.privateA);
    print_bn("Client Private Key (private)", client.privateA);
    std::cout << std::endl;

    print_bn("Server Public Key (public)", server.publicA);
    print_bn("Client Public Key (public)", client.publicA);
    std::cout << std::endl;

    print_bn("Server Shared Secret (secret)", server.secret);
    print_bn("Client Shared Secret (secret)", client.secret);
    std::cout << std::endl;
    
    return 0;
}

