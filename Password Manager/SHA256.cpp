#include <iostream>
#include <vector>
#include <bitset>
#include <cstring>
#include <sstream>
#include <iomanip>
#include <cstdint>

using namespace std;

typedef uint32_t u32;
typedef uint64_t u64;
typedef uint8_t u8;



// SHA256 konstanty
const u32 K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

static u32 ROTR(u32 x, u32 n) {
    return (x >> n) | (x << (32 - n));
}

static u32 SHR(u32 x, u32 n) {
    return x >> n;
}

static u32 Ch(u32 x, u32 y, u32 z) {
    return (x & y) ^ (~x & z);
}

static u32 Maj(u32 x, u32 y, u32 z) {
    return (x & y) ^ (x & z) ^ (y & z);
}

static u32 Σ0(u32 x) {
    return ROTR(x, 2) ^ ROTR(x, 13) ^ ROTR(x, 22);
}

static u32 Σ1(u32 x) {
    return ROTR(x, 6) ^ ROTR(x, 11) ^ ROTR(x, 25);
}

static u32 σ0(u32 x) {
    return ROTR(x, 7) ^ ROTR(x, 18) ^ SHR(x, 3);
}

static u32 σ1(u32 x) {
    return ROTR(x, 17) ^ ROTR(x, 19) ^ SHR(x, 10);
}

static vector<u8> pad_message(const string& input) {
    vector<u8> msg(input.begin(), input.end());

    u64 bit_len = msg.size() * 8;
    msg.push_back(0x80); // Přidání 1

    while ((msg.size() * 8) % 512 != 448)
        msg.push_back(0x00); // Doplňování 0

    for (int i = 7; i >= 0; --i)
        msg.push_back((bit_len >> (i * 8)) & 0xFF); // Délka zprávy

    return msg;
}

static string sha256(const string& input) {
    u32 H[8] = {
        0x6a09e667,
        0xbb67ae85,
        0x3c6ef372,
        0xa54ff53a,
        0x510e527f,
        0x9b05688c,
        0x1f83d9ab,
        0x5be0cd19
    };

    vector<u8> msg = pad_message(input);

    for (size_t i = 0; i < msg.size(); i += 64) {
        u32 W[64];
        memset(W, 0, sizeof(W));

        // Zkopírování bloku
        for (int j = 0; j < 16; ++j) {
            W[j] = (msg[i + j * 4] << 24) |
                (msg[i + j * 4 + 1] << 16) |
                (msg[i + j * 4 + 2] << 8) |
                (msg[i + j * 4 + 3]);
        }

        // Rozšíření bloku
        for (int j = 16; j < 64; ++j) {
            W[j] = σ1(W[j - 2]) + W[j - 7] + σ0(W[j - 15]) + W[j - 16];
        }

        u32 a = H[0];
        u32 b = H[1];
        u32 c = H[2];
        u32 d = H[3];
        u32 e = H[4];
        u32 f = H[5];
        u32 g = H[6];
        u32 h = H[7];

        for (int j = 0; j < 64; ++j) {
            u32 T1 = h + Σ1(e) + Ch(e, f, g) + K[j] + W[j];
            u32 T2 = Σ0(a) + Maj(a, b, c);
            h = g;
            g = f;
            f = e;
            e = d + T1;
            d = c;
            c = b;
            b = a;
            a = T1 + T2;
        }

        H[0] += a;
        H[1] += b;
        H[2] += c;
        H[3] += d;
        H[4] += e;
        H[5] += f;
        H[6] += g;
        H[7] += h;
    }

    // Výstup jako hex string
    stringstream ss;
    for (int i = 0; i < 8; ++i)
        ss << hex << setw(8) << setfill('0') << H[i];

    return ss.str();
}


