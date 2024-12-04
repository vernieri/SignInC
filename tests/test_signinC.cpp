#include <gtest/gtest.h>
#include "../src/signer.h"
#include <fstream>
#include <string>

// Helper para verificar se um arquivo existe
bool fileExists(const std::string& filename) {
    std::ifstream file(filename);
    return file.good();
}

// Teste para geração de chaves
TEST(KeyGenerationTest, GenerateKeysCreatesFiles) {
    const std::string privateKeyFile = "test_private.pem";
    const std::string publicKeyFile = "test_public.pem";

    // Gerar as chaves
    generateKeys(privateKeyFile, publicKeyFile);

    // Verificar se os arquivos foram criados
    ASSERT_TRUE(fileExists(privateKeyFile));
    ASSERT_TRUE(fileExists(publicKeyFile));

    // Limpar os arquivos de teste
    std::remove(privateKeyFile.c_str());
    std::remove(publicKeyFile.c_str());
}

// Teste para assinatura e validação de mensagens
TEST(SignatureTest, SignAndValidateMessage) {
    const std::string privateKeyFile = "test_private.pem";
    const std::string publicKeyFile = "test_public.pem";
    const std::string message = "Mensagem de teste para assinatura.";

    // Gerar as chaves
    generateKeys(privateKeyFile, publicKeyFile);

    // Assinar a mensagem
    std::string signature = signMessage(message, privateKeyFile);

    // Validar a assinatura
    ASSERT_TRUE(verifySignature(message, signature, publicKeyFile));

    // Alterar a mensagem e verificar que a assinatura não é válida
    ASSERT_FALSE(verifySignature("Mensagem alterada", signature, publicKeyFile));

    // Limpar os arquivos de teste
    std::remove(privateKeyFile.c_str());
    std::remove(publicKeyFile.c_str());
}