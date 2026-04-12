#include "password_generator.h"

#include <array>
#include <vector>
#include <random>
#include <algorithm>
#include <string>
#include <stdexcept>

namespace {
    static const std::string LOWERCASE = "abcdefghijklmnopqrstuvwxyz";
    static const std::string UPPERCASE = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    static const std::string DIGITS = "0123456789";
    static const std::string SYMBOLS = "!@#$%^&*()-_=+[]{};:,.?/\\|~";

    static const std::string AMBIGUOUS = "0Oo1lI|`'\"";

    std::string filter_ambiguous(const std::string& in, bool exclude) {
        if (!exclude) return in;
        std::string result;
        result.reserve(in.size());
        for (char c : in) {
            if (AMBIGUOUS.find(c) == std::string::npos) {
                result.push_back(c);
            }
        }
        return result;
    }


    char random_char_from(const std::string& charset, std::random_device& rd){
        if (charset.empty()) {
            throw std::runtime_error("Character set is empty. Cannot generate password.");
        }
        std::uniform_int_distribution<std::size_t> dist(0, charset.size() - 1);
        return charset[dist(rd)];
    }


    void fisher_yates_shuffle(std::string& str, std::random_device& rd) {
        if (str.empty()) return;
        for (std::size_t i = str.size() - 1; i > 0; --i) {
            std::uniform_int_distribution<std::size_t> dist(0, i);
            std::size_t j = dist(rd);
            std::swap(str[i], str[j]);
        }
    }


}

std::string generate_password(const PasswordPolicy& policy) {
    if (policy.length < 8) {
        throw std::runtime_error("Password length must be at least 8 characters. For your own good trust me bro.");
    }

    std::vector<std::string> activeSets;

    std::string lower = filter_ambiguous(LOWERCASE, policy.excludeAmbiguous);
    std::string upper = filter_ambiguous(UPPERCASE, policy.excludeAmbiguous);
    std::string digits = filter_ambiguous(DIGITS, policy.excludeAmbiguous);
    std::string symbols = filter_ambiguous(SYMBOLS, policy.excludeAmbiguous);

    if (policy.useLower) activeSets.push_back(lower);
    if (policy.useUpper) activeSets.push_back(upper);
    if (policy.useDigits) activeSets.push_back(digits);
    if (policy.useSymbols) activeSets.push_back(symbols);

    activeSets.erase(std::remove_if(activeSets.begin(), activeSets.end(), [](const std::string& s) {
        return s.empty();
    }), activeSets.end());


    if (activeSets.empty()) {
        throw std::runtime_error("At least one character set must be enabled for password generation.");
    }

    if (policy.length < activeSets.size()) {
        throw std::runtime_error("Password length must be at least equal to the number of enabled character sets to ensure each set is represented.");
    }

    std::random_device rd;

    std::string all;
    for (const auto& set : activeSets) {
        all += set;
    }

    std::string out;
    out.reserve(policy.length);

    for (const auto& set : activeSets) {
        out.push_back(random_char_from(set, rd));
    }

    while (out.size() < policy.length) {
        out.push_back(random_char_from(all, rd));
    }

    fisher_yates_shuffle(out, rd);

    return out;


}
