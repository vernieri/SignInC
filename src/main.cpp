#include "signer.h"
#include "logger.h"
#include <iostream>
#include <fstream>
#include <stdexcept>
#include <nlohmann/json.hpp>
#include "utils.h" // Inclua o cabeçalho da função Base64
using json = nlohmann::json;

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
            std::string signature = signMessage(message, privateKeyFile);

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
            bool isValid = verifySignature(message, signature, publicKeyFile);
            logger.log("A assinatura é válida? " + std::string(isValid ? "Sim" : "Não"), INFO);
        

        } else if (command == "sign-json") {
            // Novo comando para "sign-json"
            std::cout << "[DEBUG] Comando 'sign-json' chamado." << std::endl;
            std::string inputFile, privateKeyFile, outputFile;
            for (int i = 2; i < argc; ++i) {
                if (std::string(argv[i]) == "-i") {
                    inputFile = argv[++i];
                } else if (std::string(argv[i]) == "-p") {
                    privateKeyFile = argv[++i];
                } else if (std::string(argv[i]) == "-o") {
                    outputFile = argv[++i];
                }
            }
            if (inputFile.empty() || privateKeyFile.empty() || outputFile.empty()) {
                throw std::runtime_error("Por favor, forneça o arquivo JSON de entrada, chave privada e arquivo de saída.");
            }

            // Ler o JSON de entrada
            std::ifstream inFile(inputFile);
            if (!inFile.is_open()) {
                throw std::runtime_error("Erro ao abrir o arquivo JSON de entrada.");
            }
            std::string fileContent((std::istreambuf_iterator<char>(inFile)), std::istreambuf_iterator<char>());
            std::cout << "[DEBUG] Conteúdo bruto do arquivo: " << fileContent << std::endl;

            json messageJson;
            try {
                messageJson = json::parse(fileContent);
            } catch (const json::parse_error& e) {
                throw std::runtime_error("Erro ao fazer o parsing do JSON: " + std::string(e.what()));
            }
            inFile.close();

            // Serializar o JSON para string
            std::string message = messageJson.dump();
            std::cout << "[DEBUG] Mensagem serializada para assinatura: " << message << std::endl;

            // Gerar assinatura
            std::string signature;
            try {
                signature = signMessage(message, privateKeyFile);
                std::cout << "[DEBUG] Assinatura gerada: " << signature << std::endl;
            } catch (const std::exception& e) {
                throw std::runtime_error("Erro ao gerar a assinatura: " + std::string(e.what()));
            }

            // Codificar a assinatura em Base64
            std::string signatureBase64 = base64Encode(signature);
            std::cout << "[DEBUG] Assinatura codificada em Base64: " << signatureBase64 << std::endl;

            // Criar JSON de saída
            json outputJson;
            try {
                outputJson["original_message"] = messageJson;
                outputJson["signature"] = signatureBase64;
                std::cout << "[DEBUG] JSON de saída: " << outputJson.dump(4) << std::endl;
            } catch (const std::exception& e) {
                throw std::runtime_error("Erro ao construir o JSON de saída: " + std::string(e.what()));
            }

            // Salvar JSON de saída
            std::ofstream outFile(outputFile);
            if (!outFile.is_open()) {
                throw std::runtime_error("Erro ao abrir o arquivo de saída para escrita: " + outputFile);
            }
            outFile << outputJson.dump(4);
            outFile.close();

            std::cout << "[DEBUG] Arquivo de saída salvo: " << outputFile << std::endl;
            std::cout << "Mensagem JSON assinada com sucesso em " << outputFile << std::endl;



        } else if (command == "verify-json") {
            // Novo comando para "verify-json"
            std::cout << "[DEBUG] Comando 'verify-json' chamado." << std::endl;

            std::string inputFile, publicKeyFile;
            for (int i = 2; i < argc; ++i) {
                if (std::string(argv[i]) == "-i") {
                    inputFile = argv[++i];
                } else if (std::string(argv[i]) == "-u") {
                    publicKeyFile = argv[++i];
                }
            }
            if (inputFile.empty() || publicKeyFile.empty()) {
                throw std::runtime_error("Por favor, forneça o arquivo JSON de entrada e a chave pública.");
            }

            // Ler o arquivo JSON assinado
            std::ifstream inFile(inputFile);
            if (!inFile.is_open()) {
                throw std::runtime_error("Erro ao abrir o arquivo JSON assinado: " + inputFile);
            }

            json inputJson;
            try {
                inFile >> inputJson;
            } catch (const json::parse_error& e) {
                throw std::runtime_error("Erro ao fazer o parsing do JSON: " + std::string(e.what()));
            }
            inFile.close();

            // Extrair mensagem original e assinatura
            std::string originalMessage;
            std::string signatureBase64;
            try {
                originalMessage = inputJson["original_message"].dump(); // Serializa o JSON para string
                signatureBase64 = inputJson["signature"];
            } catch (const json::exception& e) {
                throw std::runtime_error("Erro ao extrair os campos do JSON: " + std::string(e.what()));
            }

            // Decodificar a assinatura de Base64
            std::string decodedSignature = base64Decode(signatureBase64);
            std::cout << "[DEBUG] Assinatura decodificada: " << decodedSignature << std::endl;

            // Validar a assinatura
            bool isValid = false;
            try {
                isValid = verifySignature(originalMessage, decodedSignature, publicKeyFile);
            } catch (const std::exception& e) {
                throw std::runtime_error("Erro ao validar a assinatura: " + std::string(e.what()));
            }

            // Exibir o resultado
            std::cout << "A assinatura é válida? " << (isValid ? "Sim" : "Não") << std::endl;

        } else {
            std::cerr << "Comando desconhecido: " << command << std::endl;
            printHelp();
        }
    } catch (const std::exception& e) {
        logger.log(std::string("Erro: ") + e.what(), ERROR);
        return 1;
    }

    logger.log("Execução concluída.", INFO);
    return 0;
}
