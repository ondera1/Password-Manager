#include <iostream>
#include <string>
#include <vector>
#include <stdexcept>
#include <fstream>

#include "database.h"
#include "password_generator.h"

static void usage() {
    std::cout
        << "Password Manager (MVP)\n"
        << "Usage:\n"
        << "  pm init <db_path>\n"
        << "  pm add  <db_path> <service> <username> <password> [note]\n"
        << "  pm list <db_path>\n"
        << "  pm find <db_path> <needle>\n"
        << "  pm rm   <db_path> <service>\n"
        << "  pm export <db_path> <out_json_path>\n"
        << "  pm import <db_path> <in_json_path>\n"
        << "  pm gen <length> [symbols yes|no] [ambiguous yes|no]\n";
}

static std::string prompt_master_password() {
    std::string pw;
    std::cout << "Master password: ";
    std::getline(std::cin, pw);
    return pw;
}

static std::string read_text_file(const std::string& path) {
    std::ifstream f(path);
    if (!f) throw std::runtime_error("Cannot open file: " + path);
    return std::string((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
}

static void write_text_file(const std::string& path, const std::string& text) {
    std::ofstream f(path, std::ios::trunc);
    if (!f) throw std::runtime_error("Cannot open file for writing: " + path);
    f << text;
    if (!f) throw std::runtime_error("Failed writing: " + path);
}

int main(int argc, char** argv) {
    try {
        if (argc < 2) {
            usage();
            return 1;
        }

        std::string cmd = argv[1];
        Database db;
        DatabaseConfig cfg;

        // -------- password generator --------
        if (cmd == "gen") {
            if (argc < 3) {
                usage();
                return 1;
            }

            PasswordPolicy p;
            p.length = static_cast<std::size_t>(std::stoul(argv[2]));

            if (argc >= 4) {
                std::string v = argv[3];
                p.useSymbols = (v == "yes" || v == "1" || v == "true");
            }

            if (argc >= 5) {
                std::string v = argv[4];
                bool allowAmbiguous = (v == "yes" || v == "1" || v == "true");
                p.excludeAmbiguous = !allowAmbiguous;
            }

            std::cout << generate_password(p) << "\n";
            return 0;
        }

        // commands below all need db_path
        if (argc < 3) {
            usage();
            return 1;
        }
        cfg.db_path = argv[2];

        // -------- init --------
        if (cmd == "init") {
            std::string master = prompt_master_password();
            db.init_new(cfg, master);
            std::cout << "Initialized DB: " << cfg.db_path << "\n";
            return 0;
        }

        // -------- add --------
        if (cmd == "add") {
            if (argc < 6) {
                usage();
                return 1;
            }

            Entry e;
            e.service = argv[3];
            e.username = argv[4];
            e.password = argv[5];
            if (argc >= 7) e.note = argv[6];

            std::string master = prompt_master_password();
            db.load(cfg, master);
            db.add(e);
            db.save(cfg, master);

            std::cout << "Saved entry for service: " << e.service << "\n";
            return 0;
        }

        // -------- list --------
        if (cmd == "list") {
            std::string master = prompt_master_password();
            db.load(cfg, master);

            for (const auto& e : db.entries()) {
                std::cout << "- " << e.service << " | " << e.username;
                if (!e.note.empty()) std::cout << " | note: " << e.note;
                std::cout << "\n";
            }
            return 0;
        }

        // -------- find --------
        if (cmd == "find") {
            if (argc < 4) {
                usage();
                return 1;
            }
            std::string needle = argv[3];

            std::string master = prompt_master_password();
            db.load(cfg, master);

            auto found = db.find_service_contains(needle);
            for (const auto& e : found) {
                std::cout << "- " << e.service << " | " << e.username << " | " << e.password;
                if (!e.note.empty()) std::cout << " | note: " << e.note;
                std::cout << "\n";
            }
            return 0;
        }

        // -------- rm --------
        if (cmd == "rm") {
            if (argc < 4) {
                usage();
                return 1;
            }
            std::string service = argv[3];

            std::string master = prompt_master_password();
            db.load(cfg, master);

            bool removed = db.remove_by_service(service);
            if (!removed) {
                std::cout << "No such service: " << service << "\n";
                return 2;
            }

            db.save(cfg, master);
            std::cout << "Removed: " << service << "\n";
            return 0;
        }

        // -------- export --------
        if (cmd == "export") {
            if (argc < 4) {
                usage();
                return 1;
            }
            std::string outPath = argv[3];

            std::string master = prompt_master_password();
            db.load(cfg, master);

            write_text_file(outPath, db.export_json_pretty());
            std::cout << "Exported plaintext JSON to: " << outPath << "\n";
            return 0;
        }

        // -------- import --------
        if (cmd == "import") {
            if (argc < 4) {
                usage();
                return 1;
            }
            std::string inPath = argv[3];

            std::string jsonText = read_text_file(inPath);
            db.import_json(jsonText);

            std::string master = prompt_master_password();
            db.save(cfg, master);

            std::cout << "Imported JSON into encrypted DB: " << cfg.db_path << "\n";
            return 0;
        }

        usage();
        return 1;

    } catch (const std::exception& e) {
        std::cerr << "ERROR: " << e.what() << "\n";
        return 1;
    }
}