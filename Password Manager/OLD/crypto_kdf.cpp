#include <openssl/evp.h>
#include <openssl/rand.h>
#include <stdexcept>
#include <vector>
#include <cstdint>

static std::vector<unsigned char> pbkdf2_sha256_key(
    const std::string& masterPassword,
    const unsigned char* salt, int saltLen,
    uint32_t iterations,
    int keyLenBytes // 32 for AES-256
) {
    std::vector<unsigned char> key(keyLenBytes);

    if (PKCS5_PBKDF2_HMAC(
            masterPassword.c_str(),
            static_cast<int>(masterPassword.size()),
            salt, saltLen,
            static_cast<int>(iterations),
            EVP_sha256(),
            keyLenBytes,
            key.data()
        ) != 1) {
        throw std::runtime_error("PBKDF2 failed");
    }
    return key;
}