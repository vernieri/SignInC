#ifndef SIGNER_H
#define SIGNER_H

#include <string>

// Geração de chaves
void generateKeys(const std::string& privateKeyFile, const std::string& publicKeyFile);

// Assinatura de mensagem
std::string signMessage(const std::string& message, const std::string& privateKeyFile);

// Validação de assinatura
bool verifySignature(const std::string& message, const std::string& signature, const std::string& publicKeyFile);

#endif // SIGNER_H