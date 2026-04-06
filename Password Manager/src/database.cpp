#include "database.h"

#include <stdexcept>
#include <fstream>
#include <sstream>
#include <algorithm>

#include "db_crypto.h"

//#include "../json/include/nlohmann/json.hpp"
#include <nlohmann/json.hpp>

using nlohmann::json;

static std::vector<uint8_t> read_all_bytes(const std::string& path) {
    std::ifstream file(path, std::ios::binary);
    if (!file) {
        throw std::runtime_error("Failed to open file: " + path);
    }

    file.seekg(0, std::ios::end);
    std::streamoff size = file.tellg();
    if (size < 0) {
        throw std::runtime_error("Failed to determine file size: " + path);
    }

    file.seekg(0, std::ios::beg);



}

