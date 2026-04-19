#include "kdf_benchmark.h"

#include <openssl/evp.h>
#include <openssl/sha.h>

#include <array>
#include <string>
#include <chrono>
#include <stdexcept>
#include <algorithm>

namespace {
    double run_once_ms(uint32_t iterations) {
        const std::string password = "benchmark_master_password";
        std::array<unsigned char,16> salt = {};
        for (size_t i = 0; i < salt.size(); ++i) salt[i] = static_cast<unsigned char>(i*17 + 23);

        std::array<unsigned char,32> output = {};

        auto t1 = std::chrono::high_resolution_clock::now();

        int ok = PKCS5_PBKDF2_HMAC(
            password.c_str(),
            static_cast<int>(password.size()),
            salt.data(),
            static_cast<int>(salt.size()),
            iterations, EVP_sha256(),
            static_cast<int>(output.size()),
            output.data()
        );

        auto t2 = std::chrono::high_resolution_clock::now();

        if (ok != 1) {
            throw std::runtime_error("PBKDF2 failed");
        }

        std::chrono::duration<double, std::milli> duration = t2 - t1;
        return duration.count();

    }

}



KdfBenchmarkResult benchmark_pbkdf2_iterations(double target_ms) {
    if (target_ms < 50.0) target_ms = 50.0;

    uint32_t iterations = 100000;

    double ms = run_once_ms(iterations);

    while (ms < target_ms && iterations < 1000000000u / 2u) {
        iterations *= 2;
        ms = run_once_ms(iterations);
    }

    uint32_t low = iterations / 2;
    uint32_t high = iterations;
    uint32_t bestIt = iterations;
    double bestMs = ms;

    for (int i = 0; i < 20; i++) {
        uint32_t mid = low + (high - low) / 2;
        double m = run_once_ms(mid);

        if (m >= target_ms){
            bestIt = mid;
            bestMs = m;
            high = mid;

        }
        else {
            low = mid +1;
        }

    }

    bestIt = std::max<uint32_t>(bestIt, 100000);

    return {bestIt, bestMs};


}