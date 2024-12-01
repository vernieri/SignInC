#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <iostream>
#include <fstream>

void generateKeys(const std::string& privateKeyFile, const std::string& publicKeyFile) {
    // Gerar par de chaves RSA
    RSA* rsa = RSA_generate_key(2048, RSA_F4, nullptr, nullptr);
    if (!rsa) {
        std::cerr << "Erro ao gerar as chaves RSA." << std::endl;
        return;
    }

    // Salvar chave privada
    FILE* privateKey = fopen(privateKeyFile.c_str(), "wb");
    PEM_write_RSAPrivateKey(privateKey, rsa, nullptr, nullptr, 0, nullptr, nullptr);
    fclose(privateKey);

    // Salvar chave pública
    FILE* publicKey = fopen(publicKeyFile.c_str(), "wb");
    PEM_write_RSA_PUBKEY(publicKey, rsa);
    fclose(publicKey);

    // Limpar memória
    RSA_free(rsa);
    std::cout << "Chaves geradas e salvas em:\n" 
              << " - " << privateKeyFile << " (Chave Privada)\n"
              << " - " << publicKeyFile << " (Chave Pública)" << std::endl;
}