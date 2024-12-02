#include "signer.h"
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <openssl/rsa.h>
#include <iostream>
#include <fstream>
#include <vector>

void generateKeys(const std::string& privateKeyFile, const std::string& publicKeyFile) {
    RSA* rsa = RSA_generate_key(2048, RSA_F4, nullptr, nullptr);
    if (!rsa) {
        throw std::runtime_error("Erro ao gerar as chaves RSA.");
    }

    // Salvar chave privada
    FILE* privateKey = fopen(privateKeyFile.c_str(), "wb");
    if (!privateKey) {
        RSA_free(rsa);
        throw std::runtime_error("Erro ao criar o arquivo de chave privada.");
    }
    PEM_write_RSAPrivateKey(privateKey, rsa, nullptr, nullptr, 0, nullptr, nullptr);
    fclose(privateKey);

    // Salvar chave pública
    FILE* publicKey = fopen(publicKeyFile.c_str(), "wb");
    if (!publicKey) {
        RSA_free(rsa);
        throw std::runtime_error("Erro ao criar o arquivo de chave pública.");
    }
    PEM_write_RSA_PUBKEY(publicKey, rsa);
    fclose(publicKey);

    RSA_free(rsa);
    std::cout << "Chaves geradas com sucesso: \n"
              << " - Chave privada: " << privateKeyFile << "\n"
              << " - Chave pública: " << publicKeyFile << std::endl;
}


std::string signMessage(const std::string& message, const std::string& privateKeyFile) {
    // Abrir a chave privada
    FILE* privateKey = fopen(privateKeyFile.c_str(), "rb");
    if (!privateKey) {
        throw std::runtime_error("Não foi possível abrir a chave privada.");
    }

    RSA* rsa = PEM_read_RSAPrivateKey(privateKey, nullptr, nullptr, nullptr);
    fclose(privateKey);

    if (!rsa) {
        throw std::runtime_error("Erro ao carregar a chave privada.");
    }

    // Calcular o hash da mensagem
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(message.c_str()), message.length(), hash);

    // Assinar o hash
    std::vector<unsigned char> signature(RSA_size(rsa));
    unsigned int signatureLen;

    if (RSA_sign(NID_sha256, hash, SHA256_DIGEST_LENGTH, signature.data(), &signatureLen, rsa) != 1) {
        RSA_free(rsa);
        throw std::runtime_error("Erro ao assinar a mensagem.");
    }

    RSA_free(rsa);

    // Retornar a assinatura como string
    return std::string(signature.begin(), signature.begin() + signatureLen);
}




bool verifySignature(const std::string& message, const std::string& signature, const std::string& publicKeyFile) {
    // Abrir a chave pública
    FILE* publicKey = fopen(publicKeyFile.c_str(), "rb");
    if (!publicKey) {
        throw std::runtime_error("Não foi possível abrir a chave pública.");
    }

    RSA* rsa = PEM_read_RSA_PUBKEY(publicKey, nullptr, nullptr, nullptr);
    fclose(publicKey);

    if (!rsa) {
        throw std::runtime_error("Erro ao carregar a chave pública.");
    }

    // Calcular o hash da mensagem
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(message.c_str()), message.length(), hash);

    // Verificar a assinatura
    int result = RSA_verify(NID_sha256, hash, SHA256_DIGEST_LENGTH,
                            reinterpret_cast<const unsigned char*>(signature.c_str()), signature.size(), rsa);

    RSA_free(rsa);

    return result == 1;
}