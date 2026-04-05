#pragma once
#include <string>
#include <vector>

#include "entry.h"

struct DatabaseConfig {
	uint32_t pbkdf2Iterations = 300000;
	std::string db_path = "passwords.db";
};

class Database {
public:
	Database() = default;

	void load(const DatabaseConfig& config, const std::string& masterPassword);

	void init_new(const DatabaseConfig& cfg, const std::string& masterPassword);

	void save(const DatabaseConfig& config, const std::string& masterPassword);

	// CRUD operace
	void add(Entry e);

	bool remove_by_service(const std::string& service);
	std::vector<Entry> find_service_contains(const std::string& substring);

	const std::vector<Entry>& entries() const { return _entries; }

	std::string export_json_pretty() const;

	void import_json(const std::string& jsonText);

private:
	std::vector<Entry> _entries;

};