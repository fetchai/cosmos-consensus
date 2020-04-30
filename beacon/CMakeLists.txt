# CMake build : mcl crypto library
cmake_minimum_required(VERSION 3.2)
project(crypto-mcl VERSION 0.5 LANGUAGES CXX ASM C)

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# define library containing a strict subset of the native interface which is needed for the trusted dealer
add_library(crypto-mcl
    "mcl_crypto.hpp"
    "mcl_crypto.cpp"
    "aeon_exec_unit.hpp"
    "aeon_exec_unit.cpp"
)
target_include_directories(crypto-mcl PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(crypto-mcl PUBLIC -lmcl -lgmp)

# trusted dealer helper library
add_executable (trusted-dealer "trusted_dealer/main.cpp")
target_link_libraries (trusted-dealer PRIVATE crypto-mcl)
