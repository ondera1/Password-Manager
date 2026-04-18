#include "database.h"

#include <stdexcept>
#include <fstream>
#include <sstream>
#include <algorithm>

#include "db_crypto.h"

//#include "../json/include/nlohmann/json.hpp"
#include <nlohmann/json.hpp>

using nlohmann::json;

////////////////////////////////
/// Pomocné funkce pro čtení a zápis binárních dat, převod mezi Entry a JSON
////////////////////////////////

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

    std::vector<uint8_t> data((size_t)size);
    if(size > 0) {
        file.read(reinterpret_cast<char*>(data.data()), size);
        if (!file) {
            throw std::runtime_error("Failed to read file: " + path);
        }
    }

    return data;


}

// Pomocná metoda pro atomické zápisy - nejdříve se zapíše do dočasného souboru a pak se přejmenuje na cílový název
static void write_all_bytes_atomic(const std::string& path, const std::vector<uint8_t>& bytes) {

    const std::string tmp = path + ".tmp";

    {
        std::ofstream file(tmp, std::ios::binary | std::ios::trunc);
        if (!file) {
            throw std::runtime_error("Failed to open file for writing: " + tmp);
        }

        if (!bytes.empty()){
            file.write(reinterpret_cast<const char*>(bytes.data()), (std::streamsize)bytes.size());
            if (!file) throw std::runtime_error("Failed to write data to file: " + tmp);
        }


    }

    std::remove(path.c_str()); // Odstranění původního souboru
    if (std::rename(tmp.c_str(), path.c_str()) != 0) {
        throw std::runtime_error("Failed to rename temp file to target file: " + tmp + " -> " + path);
    }
}

static json entry_to_json(const Entry& e) {
    return json{
        {"service", e.service},
        {"username", e.username},
        {"password", e.password},
        {"note", e.note}
    };
}



static Entry entry_from_json(const json& j) {
    Entry e;
        e.service = j.at("service").get<std::string>();
        e.username = j.at("username").get<std::string>();
        e.password = j.at("password").get<std::string>();
        if (j.contains("note")) e.note = j.at("note").get<std::string>();
    return e;
}


std::string Database::export_json_pretty() const {
    json root;
    root["version"] = 1;
    root["entries"] = json::array();
    for (const auto& e : _entries) {
        root["entries"].push_back(entry_to_json(e));
    }
    return root.dump(2); // 2 mezery pro odsazení
}

void Database::import_json(const std::string& jsonText) {
    json root = json::parse(jsonText);
    if (!root.contains("version") || root["version"].get<int>() != 1) {
        throw std::runtime_error("Unsupported database version");
    }
    if (!root.contains("entries") || !root["entries"].is_array()) {
        throw std::runtime_error("Invalid database format: missing entries array");
    }

    std::vector<Entry> newEntries;
    for (const auto& item : root.at("entries")) {
        newEntries.push_back(entry_from_json(item));
    }
    _entries = std::move(newEntries);
}

////////////////////////////
/// Database.h
////////////////////////////

void Database::load(const DatabaseConfig& config, const std::string& masterPassword) {
    
    std::vector<uint8_t> fileBytes = read_all_bytes(config.db_path);

    std::vector<uint8_t> plaintextBytes = decrypt_db(masterPassword, fileBytes);

    std::string jsonText(plaintextBytes.begin(), plaintextBytes.end());
    import_json(jsonText);
}

void Database::init_new(const DatabaseConfig& cfg, const std::string& masterPassword) {
    _entries.clear();
    save(cfg, masterPassword);
}


void Database::save(const DatabaseConfig& config, const std::string& masterPassword) const {
    std::string jsonText = export_json_pretty();
    std::vector<uint8_t> plaintextBytes(jsonText.begin(), jsonText.end());

    std::vector<uint8_t> encryptedBytes = encrypt_db(masterPassword, plaintextBytes, config.pbkdf2Iterations);

    write_all_bytes_atomic(config.db_path, encryptedBytes);
}



void Database::add(const Entry& e) {
    auto it = std::find_if(_entries.begin(), _entries.end(), [&](const Entry& existing) {
        return existing.service == e.service;
    });

    if (it != _entries.end()) {
        *it = e; 
    } else {
        _entries.push_back(e); 
    }
}



bool Database::remove_by_service(const std::string& service) {
    auto it = std::remove_if(_entries.begin(), _entries.end(), [&](const Entry& e) {
        return e.service == service;
    });

    if (it != _entries.end()) {
        _entries.erase(it, _entries.end());
        return true;
    }
    return false;
}


std::vector<Entry> Database::find_service_contains(const std::string& substring) {
    std::vector<Entry> results;
    for (const auto& e : _entries) {
        if (e.service.find(substring) != std::string::npos) {
            results.push_back(e);
        }
    }
    return results;
}

void Database::add_or_replace(const Entry& e) {
    auto it = std::find_if(_entries.begin(), _entries.end(), [&](const Entry& existing) {
        return existing.service == e.service && existing.username == e.username;
    });

    if (it != _entries.end()) {
        *it = e; 
    } else {
        _entries.push_back(e); 
    }
}

bool Database::remove(const std::string& service, const std::string& username) {
    auto it = std::remove_if(_entries.begin(), _entries.end(), [&](const Entry& e) {
        return e.service == service && e.username == username;
    });

    if (it != _entries.end()) {
        _entries.erase(it, _entries.end());
        return true;
    }
    return false;
}

bool Database::update(const std::string& service, const std::string& username, const Entry& updated) {
    auto it = std::find_if(_entries.begin(), _entries.end(), [&](const Entry& e) {
        return e.service == service && e.username == username;
    });

    if (it == _entries.end()) {
        return false;
    }
    it->username = updated.username;
    it->password = updated.password;
    it->note = updated.note;
    return true;
}



std::optional<Entry> Database::find_exact(const std::string& service, const std::string& username) const {
    auto it = std::find_if(_entries.begin(), _entries.end(), [&](const Entry& e) {
        return e.service == service && e.username == username;
    });

    if (it != _entries.end()) {
        return *it;
    }
    return std::nullopt;
}