#configure directories
set(LIB_NAME "CryptoMcl")
set(LIBRARY_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}")
set(LIBRARY_SRC_PATH "${LIBRARY_MODULE_PATH}/src")
set(LIBRARY_INCLUDE_PATH "${LIBRARY_MODULE_PATH}/include")

#set sources
file(GLOB LIB_HEADER_FILES "${LIBRARY_INCLUDE_PATH}/*.hpp")
file(GLOB LIB_SOURCE_FILES "${LIBRARY_SRC_PATH}/*.cpp")

#set library
add_library(${LIB_NAME} ${LIB_HEADER_FILES} ${LIB_SOURCE_FILES})

target_include_directories(${LIB_NAME} PUBLIC ${LIBRARY_INCLUDE_PATH})
target_link_libraries(${LIB_NAME} vendor-mcl Boost::serialization)

set(LIBRARY_INCLUDE_PATH ${LIBRARY_INCLUDE_PATH} PARENT_SCOPE)
set(LIB_NAME ${LIB_NAME} PARENT_SCOPE)