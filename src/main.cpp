#include "signer.h"
#include <iostream>
#include <fstream>

void printHelp() {
    std::cout << "Uso do SignInC:\n"
              << "  ./SignInC generate-keys -p <private_key_file> -u <public_key_file>\n"
              << "  ./SignInC sign -m <message> -p <private_key_file> -o <signature_file>\n"
              << "  ./SignInC verify -m <message> -s <signature_file> -u <public_key_file>\n";
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        printHelp();
        return 1;
    }

    std::string command = argv[1];

    try {
        if (command == "generate-keys") {
            std::string privateKeyFile, publicKeyFile;
            for (int i = 2; i < argc; ++i) {
                if (std::string(argv[i]) == "-p") {
                    privateKeyFile = argv[++i];
                } else if (std::string(argv[i]) == "-u") {
                    publicKeyFile = argv[++i];
                }
            }
            if (privateKeyFile.empty() || publicKeyFile.empty()) {
                throw std::runtime_error("Por favor, forneça os arquivos de chave com -p e -u.");
            }
            generateKeys(privateKeyFile, publicKeyFile);
        } else if (command == "sign") {
            std::string message, privateKeyFile, signatureFile;
            for (int i = 2; i < argc; ++i) {
                if (std::string(argv[i]) == "-m") {
                    message = argv[++i];
                } else if (std::string(argv[i]) == "-p") {
                    privateKeyFile = argv[++i];
                } else if (std::string(argv[i]) == "-o") {
                    signatureFile = argv[++i];
                }
            }
            if (message.empty() || privateKeyFile.empty() || signatureFile.empty()) {
                throw std::runtime_error("Por favor, forneça a mensagem, chave privada e arquivo de saída.");
            }
            std::string signature = signMessage(message, privateKeyFile);
            std::ofstream outFile(signatureFile);
            outFile << signature;
            outFile.close();
            std::cout << "Mensagem assinada com sucesso. Assinatura salva em " << signatureFile << std::endl;
        } else if (command == "verify") {
            std::string message, signatureFile, publicKeyFile;
            for (int i = 2; i < argc; ++i) {
                if (std::string(argv[i]) == "-m") {
                    message = argv[++i];
                } else if (std::string(argv[i]) == "-s") {
                    signatureFile = argv[++i];
                } else if (std::string(argv[i]) == "-u") {
                    publicKeyFile = argv[++i];
                }
            }
            if (message.empty() || signatureFile.empty() || publicKeyFile.empty()) {
                throw std::runtime_error("Por favor, forneça a mensagem, assinatura e chave pública.");
            }
            std::ifstream inFile(signatureFile);
            std::string signature((std::istreambuf_iterator<char>(inFile)),
                                   std::istreambuf_iterator<char>());
            inFile.close();
            bool isValid = verifySignature(message, signature, publicKeyFile);
            std::cout << "A assinatura é válida? " << (isValid ? "Sim" : "Não") << std::endl;
        } else {
            printHelp();
        }
    } catch (const std::exception& e) {
        std::cerr << "Erro: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}
