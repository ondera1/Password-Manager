cmake_minimum_required(VERSION 3.16)
project(PasswordManager CXX)

set(CMAKE_CXX_STANDARD 17)

find_package(OpenSSL REQUIRED)

add_executable(pm Crypto.cpp crypto_kdf.cpp "Password Manager.cpp")
target_link_libraries(pm PRIVATE OpenSSL::Crypto)