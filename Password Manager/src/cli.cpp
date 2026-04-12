#include <iostream>
#include <string>
#include <limits>

#include "database.h"
#include "password_generator.h"

static std::string prompt_line(const std::string& label) {
    std::string s;
    std::cout << label;
    std::getline(std::cin, s);
    return s;
}

static std::string prompt_master_password() {
    return prompt_line("Master password: ");
}

static void print_menu() {
    std::cout << "\n=== Password Manager ===\n"
              << "1) List entries\n"
              << "2) Add entry\n"
              << "3) Find entries\n"
              << "4) Remove entry\n"
              << "5) Generate password\n"
              << "6) Save\n"
              << "7) Lock (re-enter master password)\n"
              << "8) Exit\n"
              << "Choice: ";
}

static void list_entries(const Database& db) {
    const auto& es = db.entries();
    if (es.empty()) {
        std::cout << "(No entries)\n";
        return;
    }

    for (size_t i = 0; i < es.size(); ++i) {
        std::cout << i + 1 << ") "
                  << es[i].service << " | "
                  << es[i].username;
        if (!es[i].note.empty()) std::cout << " | note: " << es[i].note;
        std::cout << "\n";
    }
}

static void add_entry(Database& db) {
    Entry e;
    e.service  = prompt_line("Service: ");
    e.username = prompt_line("Username: ");

    std::string mode = prompt_line("Password mode [manual/gen]: ");
    if (mode == "gen") {
        PasswordPolicy p;
        std::string lenStr = prompt_line("Length (default 20): ");
        if (!lenStr.empty()) p.length = static_cast<size_t>(std::stoul(lenStr));

        std::string sym = prompt_line("Use symbols? [yes/no, default yes]: ");
        if (!sym.empty()) p.useSymbols = (sym == "yes" || sym == "y" || sym == "1" || sym == "true");

        e.password = generate_password(p);
        std::cout << "Generated password: " << e.password << "\n";
    } else {
        e.password = prompt_line("Password: ");
    }

    e.note = prompt_line("Note (optional): ");

    db.add(e);
    std::cout << "Entry saved in memory (remember to Save).\n";
}

static void find_entries(Database& db) {
    std::string needle = prompt_line("Find service contains: ");
    auto found = db.find_service_contains(needle);

    if (found.empty()) {
        std::cout << "No results.\n";
        return;
    }

    for (const auto& e : found) {
        std::cout << "- " << e.service << " | " << e.username
                  << " | password: " << e.password;
        if (!e.note.empty()) std::cout << " | note: " << e.note;
        std::cout << "\n";
    }
}

static void remove_entry(Database& db) {
    std::string service = prompt_line("Service to remove: ");
    if (db.remove_by_service(service)) {
        std::cout << "Removed (in memory). Remember to Save.\n";
    } else {
        std::cout << "Service not found.\n";
    }
}

int main() {
    try {
        Database db;
        DatabaseConfig cfg;

        cfg.db_path = prompt_line("DB path [default passwords.pmdb]: ");
        if (cfg.db_path.empty()) cfg.db_path = "passwords.pmdb";

        std::string master = prompt_master_password();

        // attempt load; if fail, offer init
        try {
            db.load(cfg, master);
            std::cout << "DB loaded.\n";
        } catch (const std::exception& e) {
            std::cout << "Load failed: " << e.what() << "\n";
            std::string createNew = prompt_line("Create new DB here? [yes/no]: ");
            if (createNew == "yes" || createNew == "y") {
                db.init_new(cfg, master);
                std::cout << "New DB initialized.\n";
            } else {
                std::cout << "Exiting.\n";
                return 1;
            }
        }

        while (true) {
            print_menu();

            int choice = 0;
            if (!(std::cin >> choice)) {
                std::cin.clear();
                std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
                std::cout << "Invalid input.\n";
                continue;
            }
            std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');

            switch (choice) {
                case 1:
                    list_entries(db);
                    break;
                case 2:
                    add_entry(db);
                    break;
                case 3:
                    find_entries(db);
                    break;
                case 4:
                    remove_entry(db);
                    break;
                case 5: {
                    PasswordPolicy p;
                    std::string lenStr = prompt_line("Length (default 20): ");
                    if (!lenStr.empty()) p.length = static_cast<size_t>(std::stoul(lenStr));
                    std::string sym = prompt_line("Use symbols? [yes/no, default yes]: ");
                    if (!sym.empty()) p.useSymbols = (sym == "yes" || sym == "y" || sym == "1" || sym == "true");
                    std::string pass = generate_password(p);
                    std::cout << "Generated password: " << pass << "\n";
                    break;
                }
                case 6:
                    db.save(cfg, master);
                    std::cout << "Saved.\n";
                    break;
                case 7: {
                    // lock: forget db in memory and ask master again
                    db = Database{};
                    std::string newMaster = prompt_master_password();
                    db.load(cfg, newMaster); // throws if wrong
                    master = std::move(newMaster);
                    std::cout << "Unlocked.\n";
                    break;
                }
                case 8: {
                    std::string save = prompt_line("Save before exit? [yes/no]: ");
                    if (save == "yes" || save == "y") {
                        db.save(cfg, master);
                        std::cout << "Saved.\n";
                    }
                    std::cout << "Bye.\n";
                    return 0;
                }
                default:
                    std::cout << "Unknown choice.\n";
                    break;
            }
        }

    } catch (const std::exception& e) {
        std::cerr << "FATAL: " << e.what() << "\n";
        return 1;
    }
}