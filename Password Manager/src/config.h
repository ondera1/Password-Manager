#pragma once
#include <string>
#include <cstdint>

struct AppConfig {
    std::string db_path = "passwords.pmdb";
    uint32_t pbkdf2_iterations = 300000;
    int idle_timeout_seconds = 120;
    std::string theme = "default";
};

AppConfig load_config_or_create_default(const std::string& path);
void save_config(const std::string& path, const AppConfig& cfg);