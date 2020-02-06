#configure variables
set (APP_NAME "TrustedDealer")

#configure directories
set (APP_MODULE_PATH "${PROJECT_SOURCE_DIR}/apps")
set (APP_SRC_PATH  "${APP_MODULE_PATH}" )

#set target executable
add_executable (${APP_NAME} "${APP_SRC_PATH}/trusted_dealer.cpp")

#add the library
target_link_libraries (${APP_NAME} ${LIB_NAME})