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

enable_testing()

# Adicione um executável para os testes
add_executable(test_signinC tests/test_signinC.cpp src/signer.cpp)

# Link com Google Test e bibliotecas do sistema
target_link_libraries(test_signinC gtest gtest_main pthread ssl crypto)

# Adicione os testes ao sistema de build
add_test(NAME SignInCTests COMMAND test_signinC)