#pragma once
#include <vector>

struct GcmEncrypted {
    std::vector<unsigned char> nonce;      // 12
    std::vector<unsigned char> ciphertext; // N
    std::vector<unsigned char> tag;        // 16
};

GcmEncrypted aes256gcm_encrypt(
    const std::vector<unsigned char>& key, // 32
    const std::vector<unsigned char>& plaintext
);

std::vector<unsigned char> aes256gcm_decrypt(
    const std::vector<unsigned char>& key, // 32
    const std::vector<unsigned char>& nonce, // 12
    const std::vector<unsigned char>& ciphertext,
    const std::vector<unsigned char>& tag // 16
);