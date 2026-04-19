#pragma once
#include <cstdint>

struct KdfBenchmarkResult {
    uint32_t recommended_iterations;
    double measured_ms;
};

KdfBenchmarkResult benchmark_pbkdf2_iterations(double target_ms = 500.0);