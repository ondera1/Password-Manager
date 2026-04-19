#include <iostream>
#include <string>
#include <limits>
#include <thread>
#include <atomic>
#include <mutex>
#include <chrono>
#include <thread>
#include <atomic>
#include <mutex>
#include <optional>
#include <fstream>

#include "database.h"
#include "password_generator.h"
#include "config.h"
#include "kdf_benchmark.h"

//// Thread

std::thread saveThread;
std::atomic<bool> saveInProgress{false};
std::atomic<bool> saveDone{false};
std::atomic<bool> saveOk{false};
std::string saveError;
std::mutex saveErrMtx;





////// --- CLI logic





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
              << "3) Edit entry\n"
              << "4) Find entries\n"
              << "5) Remove entry\n"
              << "6) Generate password\n"
              << "7) Save\n"
              << "8) Lock (re-enter master password)\n"
              << "9) Exit\n"
              << "10) Change master password\n"
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

std::mutex mtx;
std::atomic<bool> running{true};
std::atomic<bool> locked{false};

auto last_activity = std::chrono::steady_clock::now();
const auto timeout = std::chrono::minutes(5);

auto touch_activity = []() {

    std::lock_guard<std::mutex> lock(mtx);
    last_activity = std::chrono::steady_clock::now();
};

std::thread idleWatcher([]() {
    while (running) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
        std::lock_guard<std::mutex> lock(mtx);
        if (!locked && std::chrono::steady_clock::now() - last_activity > timeout) {
            locked = true;
        }
    }
});


static void edit_entry(Database& db) {
    std::string service = prompt_line("Service: ");
    std::string username = prompt_line("Current username: ");

    auto existing = db.find_exact(service, username);
    if (!existing.has_value()) {
        std::cout << "Entry not found.\n";
        return;
    }

    Entry updated = existing.value();

    // --- username
    std::string newUsername = prompt_line("New username (empty = keep): ");
    if (!newUsername.empty() && newUsername != username) {
        // kolizní kontrola: nesmí existovat (service + newUsername)
        if (db.find_exact(service, newUsername).has_value()) {
            std::cout << "Cannot rename: entry with this service+username already exists.\n";
            return;
        }
        updated.username = newUsername;
    }

    // --- password
    std::string mode = prompt_line("New password mode [keep/manual/gen] (default keep): ");
    if (mode == "manual") {
        updated.password = prompt_line("New password: ");
    } else if (mode == "gen") {
        PasswordPolicy p;
        std::string lenStr = prompt_line("Length (default 20): ");
        if (!lenStr.empty()) p.length = static_cast<size_t>(std::stoul(lenStr));

        std::string sym = prompt_line("Use symbols? [yes/no, default yes]: ");
        if (!sym.empty()) p.useSymbols = (sym == "yes" || sym == "y" || sym == "1" || sym == "true");

        updated.password = generate_password(p);
        std::cout << "Generated password: " << updated.password << "\n";
    } // keep => nic

    // --- note
    std::string note = prompt_line("New note (empty = keep, single '-' = clear): ");
    if (note == "-") updated.note.clear();
    else if (!note.empty()) updated.note = note;

    if (!db.update(service, username, updated)) {
        std::cout << "Update failed.\n";
        return;
    }

    std::cout << "Updated in memory (remember to Save).\n";
}



auto start_async_save = [](const Database& dbCurrent, const DatabaseConfig& dbCfg, const std::string& master){
    if (saveInProgress.load()) {
        std::cout << "Save already in progress. Please wait.\n";
        return;
    }

    if (saveThread.joinable()) saveThread.join();

    Database snapshot;

    snapshot.import_json(dbCurrent.export_json_pretty());

    saveInProgress.store(true);
    saveDone.store(false);
    saveOk.store(false);

    {
        std::lock_guard<std::mutex> lock(saveErrMtx);
        saveError.clear();
    }

    std::cout << "Saving...\n";

    saveThread = std::thread([snapshot = std::move(snapshot), dbCfg, master]() mutable {
        try {
            snapshot.save(dbCfg, master);
            saveOk.store(true);
        } catch (const std::exception& e) {
            saveOk.store(false);
            std::lock_guard<std::mutex> lock(saveErrMtx);
            saveError = e.what();
        }
        saveDone.store(true);
        saveInProgress.store(false);
    });

    std::cout << "Saved succesfully. \n";



};

static bool file_exists(const std::string& path) {
    std::ifstream f(path);
    return static_cast<bool>(f);
}

static bool change_master_password (Database& db, const DatabaseConfig& cfg, std::string& master) {
    std::string current = prompt_line("Current master password: ");

    if (current != master) {
        try {
            Database probe;
            probe.load(cfg, current);
        }
        catch (const std::exception& e) {
            std::cout << "Incorrect master password.\n";
            return false;
        }

    }

    std::string p1 = prompt_line("New master password: ");
    std::string p2 = prompt_line("Repeat new master password: ");
    
    if (p1.empty()) {
        std::cout << "Master password cannot be empty.\n";
        return false;
    }

    if (p1 != p2) {
        std::cout << "Passwords do not match.\n";
        return false;
    }

    if (p1 == master) {
        std::cout << "New master password is the same as the current one.\n";
        return false;
    }

    try {
        db.save(cfg, p1);
        master = std::move(p1);
        std::cout << "Master password changed successfully.\n";
        return true;
    } catch (const std::exception& e) {
        std::cout << "Failed to save with new master password: " << e.what() << "\n";
        return false;
    }

}



int main() {
    try {
        Database db;
        DatabaseConfig cfg;

        const std::string configPath = "config.json";

        AppConfig appCfg;

        if (!file_exists(configPath)) {
            std::cout << "Config file not found: " << configPath << "\n";
            std::string ans = prompt_line("Run KDF benchmark now? [yes/no]: ");

            if (ans == "yes" || ans == "y") {
                std::cout << "Benchmarking PBKDF2... please wait.\n";
                auto r = benchmark_pbkdf2_iterations(350.0);

                appCfg = AppConfig{};
                appCfg.pbkdf2_iterations = r.recommended_iterations;

                save_config(configPath, appCfg);
                std::cout << "Config created with benchmarked iterations: "
                          << appCfg.pbkdf2_iterations
                          << " (measured ~" << r.measured_ms << " ms)\n";
            } else {
                appCfg = AppConfig{}; // default
                save_config(configPath, appCfg);
                std::cout << "Default config created: " << configPath << "\n";
            }
        } else {
            appCfg = load_config_or_create_default(configPath);
            std::cout << "Config loaded: " << configPath << "\n";
        }

        cfg.db_path = appCfg.db_path;
        cfg.pbkdf2Iterations = appCfg.pbkdf2_iterations;

        //DEBUG
        std::cout << "iterations: " << cfg.pbkdf2Iterations << "\n";


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

            if (locked.load() && !(choice == 8 || choice == 9)) {
                std::cout << "Session locked due to inactivity. Please re-enter master password.\n";
                db = Database{}; // clear from memory

                std::string newMaster = prompt_master_password();
                try {
                db.load(cfg, newMaster); 
                master = std::move(newMaster);

                locked.store(false);
                touch_activity();
                std::cout << "Unlocked.\n";
                }
                catch (const std::exception& e) {
                    std::cout << "Failed to unlock: " << e.what() << "\n";
                    continue;
                }
            }


            switch (choice) {
                case 1:
                    list_entries(db);
                    break;
                case 2:
                    add_entry(db);
                    break;
                case 3:
                    edit_entry(db);
                    break;
                case 4:
                    find_entries(db);
                    break;
                case 5:
                    remove_entry(db);
                    break;
                case 6: {
                    PasswordPolicy p;
                    std::string lenStr = prompt_line("Length (default 20): ");
                    if (!lenStr.empty()) p.length = static_cast<size_t>(std::stoul(lenStr));
                    std::string sym = prompt_line("Use symbols? [yes/no, default yes]: ");
                    if (!sym.empty()) p.useSymbols = (sym == "yes" || sym == "y" || sym == "1" || sym == "true");
                    std::string pass = generate_password(p);
                    std::cout << "Generated password: " << pass << "\n";
                    break;
                }
                case 7:
                    //db.save(cfg, master);
                    start_async_save(db, cfg, master);
                    break;
                case 8: {
                    // lock: forget db in memory and ask master again
                    db = Database{};
                    std::string newMaster = prompt_master_password();
                    db.load(cfg, newMaster); // throws if wrong
                    master = std::move(newMaster);
                    std::cout << "Unlocked.\n";
                    break;
                }
                case 9: {
                    std::string save = prompt_line("Save before exit? [yes/no]: ");
                    if (save == "yes" || save == "y") {
                        //db.save(cfg, master);
                        start_async_save(db, cfg, master);
                    }
                    
                    running.store(false);
                    if (idleWatcher.joinable()) idleWatcher.join();
                    
                    if (saveInProgress.load()){
                        std::cout << "Waiting for save to finish...\n";
                    }
                    if (saveThread.joinable()) saveThread.join();
                    
                    
                    std::cout << "Bye.\n";
                    return 0;
                }
                case 10: {
                    change_master_password(db, cfg, master);
                    break;
                }
                default:
                    std::cout << "Unknown choice.\n";
                    break;
            }
            touch_activity();
        }

    } catch (const std::exception& e) {
        std::cerr << "FATAL: " << e.what() << "\n";
        return 1;
    }
}