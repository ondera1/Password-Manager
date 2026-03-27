#pragma once

#include <string>
#include <cstdint>
#include <memory>
#include <functional>
#include <iostream>
#include <utility>
#include <cstring>
#include <algorithm>
#include <vector>
#include <optional>

#include<SHA256.cpp>
#include<Crypto.cpp>

struct pass {

    std::string username;
    std::string password;

};

class User {

    private:

    int howManyPassGroups = 0;
    std::vector<std::string> passGroupsNames;

    std::string username; // username

    std::string password; //SHA 256

    std::string cipher; // cipher to cipher/decipher all passwords stored in pass_storage

    CryptoPP::SecByteBlock key;
    int blockSize = 16;

    //std::vector<pass> pass_storage; // storage for all passwords managed by user

    //std::vector<std::vector<pass>> pass_groups; // groups for passwords;
    std::vector<std::pair<std::string, std::vector<pass>>> pass_groups;

    public:

    User(std::string name, std::string passwrd){
        username = name;
        password = sha256(passwrd);
        cipher = "test";
        
        
    }

    CryptoPP::SecByteBlock generate_key(const std::string& cipher){
        return CryptoPP::SecByteBlock(reinterpret_cast<const unsigned char*> (cipher.data()),cipher.size());
    }

    bool Login(std::string name, std::string passwrd){

        if (name == username && password == sha256(passwrd)){
            return true;
        }

        return false;
    }

    bool add_pass(std::string name,std::string username, std::string passwrd, std::string group){ // i represent number of a password group where the password will be stored


        std::string encrypted = aes_encrypt(passwrd,key,blockSize);

        
        return true;
    }

    bool add_pass_group(std::string name) {
        passGroupsNames.push_back(name);
        howManyPassGroups++;

        pass_groups.emplace_back(std::vector<pass>());
    }

    std::string get_password(std::string name,int group){
        std::vector<pass> buffer = pass_groups[group];

        for (auto &item : buffer){
            
        }



    }

    





};
