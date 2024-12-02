#ifndef SIGNER_H
#define SIGNER_H

#include <string>



// Geração de chaves (já implementado)
void generateKeys(const std::string& privateKeyFile, const std::string& publicKeyFile);

// Assinar uma mensagem
std::string signMessage(const std::string& message, const std::string& privateKeyFile);

// Verificar uma assinatura
bool verifySignature(const std::string& message, const std::string& signature, const std::string& publicKeyFile);

#endif // SIGNER_H