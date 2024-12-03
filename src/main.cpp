#include "signer.h"
#include "logger.h"
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
std::string loadFile(const std::string& filename, Logger& logger) {
    std::ifstream file(filename);
    if (!file.is_open()) {
        logger.log("Erro ao abrir o arquivo: " + filename, ERROR);
        throw std::runtime_error("Arquivo não encontrado: " + filename);
    }
    std::string content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    file.close();
    logger.log("Arquivo carregado com sucesso: " + filename, INFO);
    return content;
}

int main(int argc, char* argv[]) {
    Logger logger("signinC.log");

    if (argc < 2) {
        logger.log("Número insuficiente de argumentos.", ERROR);
        printHelp();
        return 1;
    }

    std::string command = argv[1];
    logger.log("Comando recebido: " + command, INFO);

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
                logger.log("Arquivos de chave não fornecidos com -p e -u.", ERROR);
                throw std::runtime_error("Por favor, forneça os arquivos de chave com -p e -u.");
            }
            logger.log("Gerando chaves...", INFO);
            generateKeys(privateKeyFile, publicKeyFile);
            logger.log("Chaves geradas com sucesso.", INFO);

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
                logger.log("Argumentos ausentes para o comando 'sign'.", ERROR);
                throw std::runtime_error("Por favor, forneça o arquivo de entrada, chave privada e arquivo de saída.");
            }

            // Carregar mensagem do arquivo
            logger.log("Carregando mensagem do arquivo: " + inputFile, INFO);
            std::string message = loadFile(inputFile, logger);

            // Gerar assinatura
            logger.log("Assinando a mensagem...", INFO);
            std::string signature = signMessage(message, privateKeyFile, logger);

            // Salvar assinatura no arquivo
            std::ofstream outFile(signatureFile);
            if (!outFile.is_open()) {
                logger.log("Erro ao salvar a assinatura em: " + signatureFile, ERROR);
                throw std::runtime_error("Não foi possível salvar a assinatura em: " + signatureFile);
            }
            outFile << signature;
            outFile.close();
            logger.log("Mensagem assinada com sucesso. Assinatura salva em " + signatureFile, INFO);

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
                logger.log("Argumentos ausentes para o comando 'verify'.", ERROR);
                throw std::runtime_error("Por favor, forneça o arquivo de entrada, assinatura e chave pública.");
            }

            // Carregar mensagem e assinatura
            logger.log("Carregando mensagem do arquivo: " + inputFile, INFO);
            std::string message = loadFile(inputFile, logger);
            logger.log("Carregando assinatura do arquivo: " + signatureFile, INFO);
            std::string signature = loadFile(signatureFile, logger);

            // Verificar a assinatura
            logger.log("Verificando a assinatura...", INFO);
            bool isValid = verifySignature(message, signature, publicKeyFile, logger);
            logger.log("A assinatura é válida? " + std::string(isValid ? "Sim" : "Não"), INFO);

        } else {
            logger.log("Comando desconhecido: " + command, ERROR);
            printHelp();
        }
    } catch (const std::exception& e) {
        logger.log(std::string("Erro: ") + e.what(), ERROR);
        return 1;
    }

    logger.log("Execução concluída.", INFO);
    return 0;
}
