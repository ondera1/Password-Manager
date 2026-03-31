
#pragma once
#include <cstdint>
#include <string>
#include <vector>

std::vector<uint8_t> encrypt_db(
    const std::string& masterPassword,
    const std::vector<uint8_t>& plaintext,
    uint32_t pbkdf2Iterations = 300000
);

std::vector<uint8_t> decrypt_db(
    const std::string& masterPassword,
    const std::vector<uint8_t>& fileBytes
);