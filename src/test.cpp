#include "signer.h"
#include <iostream>

int main() {
    try {
        // Gerar as chaves
        generateKeys("private.pem", "public.pem");

        // Mensagem para assinar
        std::string message = "Mensagem de teste para assinatura digital.";

        // Assinar a mensagem
        std::string signature = signMessage(message, "private.pem");
        std::cout << "Assinatura gerada com sucesso: " << signature << std::endl;

        // Verificar a assinatura
        bool isValid = verifySignature(message, signature, "public.pem");
        std::cout << "A assinatura é válida? " << (isValid ? "Sim" : "Não") << std::endl;
    } catch (const std::exception& e) {
        std::cerr << "Erro: " << e.what() << std::endl;
    }

    return 0;
}