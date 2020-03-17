# CMake build : mcl crypto library
cmake_minimum_required(VERSION 3.2)
project(Test VERSION 0.5 LANGUAGES CXX ASM C)
set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

#configure directories
set(LIB_NAME "CryptoMcl")
set(LIBRARY_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}")
set(LIBRARY_SRC_PATH "${LIBRARY_MODULE_PATH}")
set(LIBRARY_INCLUDE_PATH "${LIBRARY_MODULE_PATH}")

#set sources
set(LIB_HEADER_FILES "mcl_crypto.hpp" "aeon_exec_unit.hpp")
set(LIB_SOURCE_FILES "mcl_crypto.cpp" "aeon_exec_unit.cpp")

#set library
add_library(${LIB_NAME} ${LIB_HEADER_FILES} ${LIB_SOURCE_FILES})

target_include_directories(${LIB_NAME} PUBLIC ${LIBRARY_INCLUDE_PATH})
target_link_libraries(${LIB_NAME} -lmcl -lgmp)

#configure variables
set (APP_NAME "TrustedDealer")

#configure directories
set (APP_MODULE_PATH "${PROJECT_SOURCE_DIR}/beacon_cpp/trusted_dealer")
set (APP_SRC_PATH  "${APP_MODULE_PATH}")

#set target executable
add_executable (${APP_NAME} "${APP_SRC_PATH}/trusted_dealer.cpp")

#add the library
target_link_libraries (${APP_NAME} ${LIB_NAME})
