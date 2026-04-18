#include "config.h"

#include <fstream>
#include <stdexcept>
#include <nlohmann/json.hpp>

using nlohmann::json;

static bool file_exists(const std::string& path) {
    std::ifstream f(path);
    return static_cast<bool>(f);
}

void save_config(const std::string& path, const AppConfig& cfg) {
    json j;
    j["db_path"] = cfg.db_path;
    j["pbkdf2_iterations"] = cfg.pbkdf2_iterations;
    j["idle_timeout_seconds"] = cfg.idle_timeout_seconds;
    j["theme"] = cfg.theme;

    std::ofstream out(path, std::ios::trunc);
    if (!out) throw std::runtime_error("Cannot write config file: " + path);
    out << j.dump(2);
    if (!out) throw std::runtime_error("Failed writing config file: " + path);
}

AppConfig load_config_or_create_default(const std::string& path) {
    if (!file_exists(path)) {
        AppConfig def;
        save_config(path, def);
        return def;
    }

    std::ifstream in(path);
    if (!in) throw std::runtime_error("Cannot open config file: " + path);

    json j;
    in >> j;

    AppConfig cfg;

    if (j.contains("db_path")) cfg.db_path = j["db_path"].get<std::string>();
    if (j.contains("pbkdf2_iterations")) cfg.pbkdf2_iterations = j["pbkdf2_iterations"].get<uint32_t>();
    if (j.contains("idle_timeout_seconds")) cfg.idle_timeout_seconds = j["idle_timeout_seconds"].get<int>();
    if (j.contains("theme")) cfg.theme = j["theme"].get<std::string>();

    if (cfg.db_path.empty()) cfg.db_path = "passwords.pmdb";
    if (cfg.pbkdf2_iterations < 100000) cfg.pbkdf2_iterations = 100000;
    if (cfg.idle_timeout_seconds < 10) cfg.idle_timeout_seconds = 10;
    if (cfg.theme.empty()) cfg.theme = "default";

    return cfg;
}