#include <iostream>
#include <vector>
#include <bitset>
#include <cstring>
#include <sstream>
#include <iomanip>

#include "SHA256.cpp"

int main()
{
    std::string str = "nečum";
    std::string str2 = "nečum";
    std::string str3 = "necum";

    std::string hash = sha256(str);
    std::string hash2 = sha256(str2);
    std::string hash3 = sha256(str3);

    std::cout << hash << sha256 << std::endl;
    std::cout << hash2 << sha256 << std::endl;
    std::cout << hash3 << sha256 << std::endl;


    
}
