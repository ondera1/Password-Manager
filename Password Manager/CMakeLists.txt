cmake_minimum_required(VERSION 3.16)
project(PasswordManager CXX)

set(CMAKE_CXX_STANDARD 17)

find_package(OpenSSL REQUIRED)

add_executable(pm 
	src/cli.cpp
	src/database.cpp
	db_crypto.cpp
	crypto_gcm.cpp
	src/password_generator.cpp
	src/config.cpp
	src/kdf_benchmark.cpp
)

target_include_directories(pm PRIVATE
	src
	.
	json/include
	
)

target_link_libraries(pm PRIVATE OpenSSL::Crypto)