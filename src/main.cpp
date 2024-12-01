#include <iostream>
#include "signer.h"

int main() {
    std::cout << "Gerando chaves RSA..." << std::endl;
    generateKeys("private.pem", "public.pem");
    return 0;
}