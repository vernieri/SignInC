#include "signer.h"
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <openssl/rsa.h>
#include <iostream>
#include <fstream>
#include <vector>

void generateKeys(const std::string& privateKeyFile, const std::string& publicKeyFile) {
    RSA* rsa = RSA_new();
    BIGNUM* bn = BN_new();
    BN_set_word(bn, RSA_F4);

    if (RSA_generate_key_ex(rsa, 2048, bn, nullptr) != 1) {
        RSA_free(rsa);
        BN_free(bn);
        throw std::runtime_error("Erro ao gerar as chaves RSA.");
    }

    // Salvar chave privada
    FILE* privateKey = fopen(privateKeyFile.c_str(), "wb");
    PEM_write_RSAPrivateKey(privateKey, rsa, nullptr, nullptr, 0, nullptr, nullptr);
    fclose(privateKey);

    // Salvar chave pública
    FILE* publicKey = fopen(publicKeyFile.c_str(), "wb");
    PEM_write_RSA_PUBKEY(publicKey, rsa);
    fclose(publicKey);

    RSA_free(rsa);
    BN_free(bn);
}


std::string signMessage(const std::string& message, const std::string& privateKeyFile) {
    FILE* privateKey = fopen(privateKeyFile.c_str(), "rb");
    if (!privateKey) {
        throw std::runtime_error("Não foi possível abrir a chave privada.");
    }

    RSA* rsa = PEM_read_RSAPrivateKey(privateKey, nullptr, nullptr, nullptr);
    fclose(privateKey);

    if (!rsa) {
        throw std::runtime_error("Erro ao carregar a chave privada.");
    }

    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(message.c_str()), message.length(), hash);

    std::vector<unsigned char> signature(RSA_size(rsa));
    unsigned int signatureLen;

    if (RSA_sign(NID_sha256, hash, SHA256_DIGEST_LENGTH, signature.data(), &signatureLen, rsa) != 1) {
        RSA_free(rsa);
        throw std::runtime_error("Erro ao assinar a mensagem.");
    }

    RSA_free(rsa);
    return std::string(signature.begin(), signature.begin() + signatureLen);
}

bool verifySignature(const std::string& message, const std::string& signature, const std::string& publicKeyFile) {
    FILE* publicKey = fopen(publicKeyFile.c_str(), "rb");
    if (!publicKey) {
        throw std::runtime_error("Não foi possível abrir a chave pública.");
    }

    RSA* rsa = PEM_read_RSA_PUBKEY(publicKey, nullptr, nullptr, nullptr);
    fclose(publicKey);

    if (!rsa) {
        throw std::runtime_error("Erro ao carregar a chave pública.");
    }

    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(message.c_str()), message.length(), hash);

    int result = RSA_verify(NID_sha256, hash, SHA256_DIGEST_LENGTH,
                            reinterpret_cast<const unsigned char*>(signature.c_str()), signature.size(), rsa);

    RSA_free(rsa);
    return result == 1;
}