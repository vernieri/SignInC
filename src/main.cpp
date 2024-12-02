#include "signer.h"
#include <iostream>
#include <fstream>
#include <stdexcept>

// Função para exibir o manual de uso
void printHelp() {
    std::cout << "Uso do SignInC:\n"
              << "  ./SignInC generate-keys -p <private_key_file> -u <public_key_file>\n"
              << "  ./SignInC sign -i <input_file> -p <private_key_file> -o <signature_file>\n"
              << "  ./SignInC verify -i <input_file> -s <signature_file> -u <public_key_file>\n";
}

// Função para carregar o conteúdo de um arquivo
std::string loadFile(const std::string& filename) {
    std::ifstream file(filename);
    if (!file.is_open()) {
        throw std::runtime_error("Não foi possível abrir o arquivo: " + filename);
    }
    std::string content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    file.close();
    return content;
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
            std::string inputFile, privateKeyFile, signatureFile;
            for (int i = 2; i < argc; ++i) {
                if (std::string(argv[i]) == "-i") {
                    inputFile = argv[++i];
                } else if (std::string(argv[i]) == "-p") {
                    privateKeyFile = argv[++i];
                } else if (std::string(argv[i]) == "-o") {
                    signatureFile = argv[++i];
                }
            }
            if (inputFile.empty() || privateKeyFile.empty() || signatureFile.empty()) {
                throw std::runtime_error("Por favor, forneça o arquivo de entrada, chave privada e arquivo de saída.");
            }

            // Carregar mensagem do arquivo
            std::string message = loadFile(inputFile);

            // Gerar assinatura
            std::string signature = signMessage(message, privateKeyFile);

            // Salvar assinatura no arquivo
            std::ofstream outFile(signatureFile);
            if (!outFile.is_open()) {
                throw std::runtime_error("Não foi possível salvar a assinatura em: " + signatureFile);
            }
            outFile << signature;
            outFile.close();

            std::cout << "Mensagem assinada com sucesso. Assinatura salva em " << signatureFile << std::endl;

        } else if (command == "verify") {
            std::string inputFile, signatureFile, publicKeyFile;
            for (int i = 2; i < argc; ++i) {
                if (std::string(argv[i]) == "-i") {
                    inputFile = argv[++i];
                } else if (std::string(argv[i]) == "-s") {
                    signatureFile = argv[++i];
                } else if (std::string(argv[i]) == "-u") {
                    publicKeyFile = argv[++i];
                }
            }
            if (inputFile.empty() || signatureFile.empty() || publicKeyFile.empty()) {
                throw std::runtime_error("Por favor, forneça o arquivo de entrada, assinatura e chave pública.");
            }

            // Carregar mensagem e assinatura
            std::string message = loadFile(inputFile);
            std::string signature = loadFile(signatureFile);

            // Verificar a assinatura
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
