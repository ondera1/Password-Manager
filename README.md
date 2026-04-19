# Password Manager
cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug
cmake --build build -j

./build/pm

Co je splňěno ze zadání:
Database encrypted by main password
All passwords are stored in a single file
Every password entry has a name, username, password and note(optional)
User can add, edit, search and delete password entries

Program detects if database file is corrupted or the input password is wrong
Program has config file
Password generator with options for length and character types
Heavy duty operations are done in a separate thread to keep the UI responsive
Automatic session lock after a period of inactivity