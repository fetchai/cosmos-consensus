# CMake build : mcl crypto library
cmake_minimum_required(VERSION 3.2)
project(Test VERSION 0.5 LANGUAGES CXX ASM C)
set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fPIC -lboost_serialization")

set(THIRD_PARTY_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/3rd")
# mcl
set(USE_GMP OFF CACHE BOOL "use gmp" FORCE)
set(USE_OPENSSL OFF CACHE BOOL "use openssl" FORCE)
set(ONLY_LIB ON CACHE BOOL "only lib" FORCE)
add_subdirectory(${THIRD_PARTY_MODULE_PATH}/mcl)
target_include_directories(mcl_st INTERFACE ${THIRD_PARTY_MODULE_PATH}/mcl/include)
target_compile_definitions(mcl_st
        INTERFACE
        -DMCL_USE_VINT
        -DMCL_VINT_FIXED_BUFFER
        -DMCLBN_FP_UNIT_SIZE=4)

add_library(vendor-mcl INTERFACE)
target_link_libraries(vendor-mcl INTERFACE mcl_st)

add_subdirectory(libs)
add_subdirectory(apps)
