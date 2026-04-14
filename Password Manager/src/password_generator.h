#pragma once

#include <string>
#include <cstddef>

struct PasswordPolicy {
    std::size_t length = 20;
    bool useLower = true;
    bool useUpper = true;
    bool useDigits = true;
    bool useSymbols = true;

    bool excludeAmbiguous = true; // Exclude characters like 'O', '0', 'I', 'l' to avoid confusion

};

std::string generate_password(const PasswordPolicy& policy);