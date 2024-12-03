#ifndef LOGGER_H
#define LOGGER_H

#include <iostream>
#include <fstream>
#include <string>
#include <ctime>

enum LogLevel {
    INFO,
    WARN,
    ERROR
};

class Logger {
public:
    Logger(const std::string& logFile = "") : logToFile(!logFile.empty()), logFileName(logFile) {}

    void log(const std::string& message, LogLevel level) {
        std::string levelStr;
        switch (level) {
            case INFO: levelStr = "[INFO]"; break;
            case WARN: levelStr = "[WARN]"; break;
            case ERROR: levelStr = "[ERROR]"; break;
        }

        // Formatar a mensagem
        std::string formattedMessage = getCurrentTime() + " " + levelStr + " " + message;

        // Log no console
        std::cout << formattedMessage << std::endl;

        // Log em arquivo, se habilitado
        if (logToFile) {
            std::ofstream logFileStream(logFileName, std::ios_base::app);
            if (logFileStream.is_open()) {
                logFileStream << formattedMessage << std::endl;
                logFileStream.close();
            } else {
                std::cerr << "[ERROR] Não foi possível abrir o arquivo de log: " << logFileName << std::endl;
            }
        }
    }

private:
    bool logToFile;
    std::string logFileName;

    std::string getCurrentTime() {
        std::time_t now = std::time(nullptr);
        char buf[80];
        std::strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", std::localtime(&now));
        return std::string(buf);
    }
};

#endif // LOGGER_H
