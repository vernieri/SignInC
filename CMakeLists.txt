cmake_minimum_required(VERSION 3.10)
project(SignInC)

# Definir padrão C++17
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# Adicionar o executável
add_executable(SignInC src/main.cpp src/signer.cpp)

# Link com a biblioteca OpenSSL
find_package(OpenSSL REQUIRED)
target_link_libraries(SignInC OpenSSL::SSL OpenSSL::Crypto)