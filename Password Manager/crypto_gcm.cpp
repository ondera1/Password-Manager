#include "crypto_gcm.h"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <stdexcept>

GcmEncrypted aes256gcm_encrypt(const std::vector<unsigned char>& key,
                               const std::vector<unsigned char>& plaintext) {
    if (key.size() != 32) throw std::runtime_error("AES-256 key must be 32 bytes");

    GcmEncrypted out;
    out.nonce.resize(12);
    out.tag.resize(16);
    out.ciphertext.resize(plaintext.size());

    if (RAND_bytes(out.nonce.data(), (int)out.nonce.size()) != 1)
        throw std::runtime_error("RAND_bytes failed");

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) throw std::runtime_error("EVP_CIPHER_CTX_new failed");

    int len = 0;
    int outLen = 0;

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1)
        throw std::runtime_error("EncryptInit failed");
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, (int)out.nonce.size(), nullptr) != 1)
        throw std::runtime_error("SET_IVLEN failed");
    if (EVP_EncryptInit_ex(ctx, nullptr, nullptr, key.data(), out.nonce.data()) != 1)
        throw std::runtime_error("EncryptInit(key,nonce) failed");

    if (!plaintext.empty()) {
        if (EVP_EncryptUpdate(ctx, out.ciphertext.data(), &len, plaintext.data(), (int)plaintext.size()) != 1)
            throw std::runtime_error("EncryptUpdate failed");
        outLen = len;
    }

    if (EVP_EncryptFinal_ex(ctx, out.ciphertext.data() + outLen, &len) != 1)
        throw std::runtime_error("EncryptFinal failed");
    outLen += len;
    out.ciphertext.resize(outLen);

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, (int)out.tag.size(), out.tag.data()) != 1)
        throw std::runtime_error("GET_TAG failed");

    EVP_CIPHER_CTX_free(ctx);
    return out;
}

std::vector<unsigned char> aes256gcm_decrypt(const std::vector<unsigned char>& key,
                                            const std::vector<unsigned char>& nonce,
                                            const std::vector<unsigned char>& ciphertext,
                                            const std::vector<unsigned char>& tag) {
    if (key.size() != 32) throw std::runtime_error("AES-256 key must be 32 bytes");

    std::vector<unsigned char> plaintext(ciphertext.size());

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) throw std::runtime_error("EVP_CIPHER_CTX_new failed");

    int len = 0;
    int outLen = 0;

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1)
        throw std::runtime_error("DecryptInit failed");
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, (int)nonce.size(), nullptr) != 1)
        throw std::runtime_error("SET_IVLEN failed");
    if (EVP_DecryptInit_ex(ctx, nullptr, nullptr, key.data(), nonce.data()) != 1)
        throw std::runtime_error("DecryptInit(key,nonce) failed");

    if (!ciphertext.empty()) {
        if (EVP_DecryptUpdate(ctx, plaintext.data(), &len, ciphertext.data(), (int)ciphertext.size()) != 1)
            throw std::runtime_error("DecryptUpdate failed");
        outLen = len;
    }

    // očekávaný tag
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, (int)tag.size(), (void*)tag.data()) != 1)
        throw std::runtime_error("SET_TAG failed");

    int ret = EVP_DecryptFinal_ex(ctx, plaintext.data() + outLen, &len);
    EVP_CIPHER_CTX_free(ctx);

    if (ret != 1) {
        throw std::runtime_error("Decrypt failed (wrong password or corrupted DB)");
    }

    outLen += len;
    plaintext.resize(outLen);
    return plaintext;
}