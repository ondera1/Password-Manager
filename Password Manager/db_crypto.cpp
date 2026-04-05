#include "db_crypto.h"

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>

#include <array>
#include <cstring>
#include <stdexcept>



// uložení 32 bitového čísla do vektoru out ve formátu little-endian (LSB first).
// Důvod toho postupu je jednoduchý, chci zaručit funkčnost a podporu na různých zařízeních, nezávisle na Architektuře CPU.
// Také umožňuje bezpečně číst hlviku souboru.

static void write_u32_le(std::vector<uint8_t>& out, uint32_t v) {
    out.push_back((uint8_t)(v & 0xFF));
    out.push_back((uint8_t)((v >> 8) & 0xFF));
    out.push_back((uint8_t)((v >> 16) & 0xFF));
    out.push_back((uint8_t)((v >> 24) & 0xFF));
}

// Podobně jako write ale pro čtení těchto hodnot
static uint32_t read_u32_le(const std::vector<uint8_t>& in, size_t& off) {
    if (off + 4 > in.size()) throw std::runtime_error("Corrupted DB: truncated u32");
    uint32_t v = 0;
    v |= (uint32_t)in[off + 0];
    v |= (uint32_t)in[off + 1] << 8;
    v |= (uint32_t)in[off + 2] << 16;
    v |= (uint32_t)in[off + 3] << 24;
    off += 4;
    return v;
}


// Čte n bytů z in od offsetu off do bufferu dst
static void read_bytes(const std::vector<uint8_t>& in, size_t& off, uint8_t* dst, size_t n) {
    if (off + n > in.size()) throw std::runtime_error("Corrupted DB: truncated bytes");
    std::memcpy(dst, in.data() + off, n);
    off += n;
}


// Zde důležitá část programu, odvození klíče z hesla pomocí PBKDF2. 
// salt - náhodná sůl uložená v db aby nelo použít předpočítanou hash tabulku.
// Iterace dále zpomalují útok hrubou silou, ale zároveň zvyšují nároky na výkon při načítání databáze, tohle bude následně implementováno
// pomocí procesů nebo vláken aby jsme nezablokovali UI.

static std::vector<uint8_t> pbkdf2_sha256_key_32(
    const std::string& masterPassword,
    const uint8_t* salt, size_t saltLen,
    uint32_t iterations
) {
    std::vector<uint8_t> key(32);

    // Funkce PKCS5_PBKDF2_HMAC vrací 1 při úspěchu, 0 při chybě. V případě chyby vyhodíme vyjímku, protože bez správného klíče nemůžeme pokračovat.
    // Výstup této metody je klíč o délce 32 bajtů. 
    int ok = PKCS5_PBKDF2_HMAC(
        masterPassword.c_str(),
        (int)masterPassword.size(),
        salt,
        (int)saltLen,
        (int)iterations,
        EVP_sha256(), // Říká funkci, že chceme použít SHA-256 jako hashovací funkci pro PBKDF2
        (int)key.size(),
        key.data()
    );
    if (ok != 1) throw std::runtime_error("PBKDF2 failed");

    return key;
}

std::vector<uint8_t> encrypt_db(
    const std::string& masterPassword,
    const std::vector<uint8_t>& plaintext,
    uint32_t pbkdf2Iterations
) {
    // --- constants
    const std::array<uint8_t, 4> magic = {'P','M','D','B'};
    const uint32_t version = 1;
    const size_t SALT_LEN = 16;
    const size_t NONCE_LEN = 12; // recommended for GCM
    const size_t TAG_LEN = 16;

    // --- generate salt + derive key
    std::array<uint8_t, SALT_LEN> salt{};
    if (RAND_bytes(salt.data(), (int)salt.size()) != 1)
        throw std::runtime_error("RAND_bytes(salt) failed");

    std::vector<uint8_t> key = pbkdf2_sha256_key_32(masterPassword, salt.data(), salt.size(), pbkdf2Iterations);

    // --- generate nonce
    std::array<uint8_t, NONCE_LEN> nonce{};
    if (RAND_bytes(nonce.data(), (int)nonce.size()) != 1)
        throw std::runtime_error("RAND_bytes(nonce) failed");

    // --- AES-256-GCM encrypt
    std::vector<uint8_t> ciphertext(plaintext.size());
    std::array<uint8_t, TAG_LEN> tag{};

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) throw std::runtime_error("EVP_CIPHER_CTX_new failed");

    int len = 0;
    int outLen = 0;

    // optional AAD: authenticated header (magic+version+iters+salt+nonce)
    // We'll compute it after we build header bytes; easiest is to build header first
    // BUT we need tag only after encryption. We'll build AAD bytes now manually.

    std::vector<uint8_t> aad;
    aad.insert(aad.end(), magic.begin(), magic.end());
    write_u32_le(aad, version);
    write_u32_le(aad, pbkdf2Iterations);
    aad.insert(aad.end(), salt.begin(), salt.end());
    aad.insert(aad.end(), nonce.begin(), nonce.end());

    try {
        if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1)
            throw std::runtime_error("EncryptInit failed");

        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, (int)nonce.size(), nullptr) != 1)
            throw std::runtime_error("SET_IVLEN failed");

        if (EVP_EncryptInit_ex(ctx, nullptr, nullptr, key.data(), nonce.data()) != 1)
            throw std::runtime_error("EncryptInit(key,nonce) failed");

        // AAD
        if (!aad.empty()) {
            if (EVP_EncryptUpdate(ctx, nullptr, &len, aad.data(), (int)aad.size()) != 1)
                throw std::runtime_error("EncryptUpdate(AAD) failed");
        }

        if (!plaintext.empty()) {
            if (EVP_EncryptUpdate(ctx, ciphertext.data(), &len, plaintext.data(), (int)plaintext.size()) != 1)
                throw std::runtime_error("EncryptUpdate(data) failed");
            outLen = len;
        }

        if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + outLen, &len) != 1)
            throw std::runtime_error("EncryptFinal failed");
        outLen += len;
        ciphertext.resize((size_t)outLen);

        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, (int)tag.size(), tag.data()) != 1)
            throw std::runtime_error("GET_TAG failed");

        EVP_CIPHER_CTX_free(ctx);
        ctx = nullptr;

    } catch (...) {
        EVP_CIPHER_CTX_free(ctx);
        throw;
    }

    // --- build final file bytes: header + tag + ciphertext
    std::vector<uint8_t> out;
    out.reserve(4 + 4 + 4 + SALT_LEN + NONCE_LEN + TAG_LEN + ciphertext.size());

    out.insert(out.end(), magic.begin(), magic.end());
    write_u32_le(out, version);
    write_u32_le(out, pbkdf2Iterations);
    out.insert(out.end(), salt.begin(), salt.end());
    out.insert(out.end(), nonce.begin(), nonce.end());
    out.insert(out.end(), tag.begin(), tag.end());
    out.insert(out.end(), ciphertext.begin(), ciphertext.end());

    // hygiene: try to clear key from memory
    OPENSSL_cleanse(key.data(), key.size());

    return out;
}

std::vector<uint8_t> decrypt_db(
    const std::string& masterPassword,
    const std::vector<uint8_t>& fileBytes
) {
    const std::array<uint8_t, 4> magic = {'P','M','D','B'};
    const uint32_t expectedVersion = 1;
    const size_t SALT_LEN = 16;
    const size_t NONCE_LEN = 12;
    const size_t TAG_LEN = 16;

    size_t off = 0;

    // --- magic
    if (fileBytes.size() < 4) throw std::runtime_error("Not a DB file (too small)");
    if (std::memcmp(fileBytes.data(), magic.data(), magic.size()) != 0)
        throw std::runtime_error("Not a DB file (bad magic)");
    off += 4;

    // --- version + iters
    uint32_t version = read_u32_le(fileBytes, off);
    if (version != expectedVersion)
        throw std::runtime_error("Unsupported DB version");

    uint32_t iters = read_u32_le(fileBytes, off);
    if (iters < 10000) // sanity guard
        throw std::runtime_error("Corrupted DB (iters too small)");

    // --- salt, nonce, tag
    std::array<uint8_t, SALT_LEN> salt{};
    std::array<uint8_t, NONCE_LEN> nonce{};
    std::array<uint8_t, TAG_LEN> tag{};

    read_bytes(fileBytes, off, salt.data(), salt.size());
    read_bytes(fileBytes, off, nonce.data(), nonce.size());
    read_bytes(fileBytes, off, tag.data(), tag.size());

    if (off > fileBytes.size())
        throw std::runtime_error("Corrupted DB");

    std::vector<uint8_t> ciphertext(fileBytes.begin() + (long)off, fileBytes.end());

    // --- derive key
    std::vector<uint8_t> key = pbkdf2_sha256_key_32(masterPassword, salt.data(), salt.size(), iters);

    // --- rebuild AAD (must match encrypt side)
    std::vector<uint8_t> aad;
    aad.insert(aad.end(), magic.begin(), magic.end());
    write_u32_le(aad, version);
    write_u32_le(aad, iters);
    aad.insert(aad.end(), salt.begin(), salt.end());
    aad.insert(aad.end(), nonce.begin(), nonce.end());

    // --- decrypt
    std::vector<uint8_t> plaintext(ciphertext.size());

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) throw std::runtime_error("EVP_CIPHER_CTX_new failed");

    int len = 0;
    int outLen = 0;

    try {
        if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1)
            throw std::runtime_error("DecryptInit failed");

        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, (int)nonce.size(), nullptr) != 1)
            throw std::runtime_error("SET_IVLEN failed");

        if (EVP_DecryptInit_ex(ctx, nullptr, nullptr, key.data(), nonce.data()) != 1)
            throw std::runtime_error("DecryptInit(key,nonce) failed");

        // AAD
        if (!aad.empty()) {
            if (EVP_DecryptUpdate(ctx, nullptr, &len, aad.data(), (int)aad.size()) != 1)
                throw std::runtime_error("DecryptUpdate(AAD) failed");
        }

        if (!ciphertext.empty()) {
            if (EVP_DecryptUpdate(ctx, plaintext.data(), &len, ciphertext.data(), (int)ciphertext.size()) != 1)
                throw std::runtime_error("DecryptUpdate(data) failed");
            outLen = len;
        }

        // set expected tag
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, (int)tag.size(), (void*)tag.data()) != 1)
            throw std::runtime_error("SET_TAG failed");

        int ret = EVP_DecryptFinal_ex(ctx, plaintext.data() + outLen, &len);
        EVP_CIPHER_CTX_free(ctx);
        ctx = nullptr;

        if (ret != 1) {
            throw std::runtime_error("Wrong master password OR corrupted DB (GCM tag mismatch)");
        }

        outLen += len;
        plaintext.resize((size_t)outLen);

        OPENSSL_cleanse(key.data(), key.size());
        return plaintext;

    } catch (...) {
        EVP_CIPHER_CTX_free(ctx);
        OPENSSL_cleanse(key.data(), key.size());
        throw;
    }
}