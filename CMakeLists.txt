cmake_minimum_required(VERSION 3.10)

# set the project name
project(netpune)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED true)
set_property(TARGET ${TARGET_NAME} PROPERTY CXX_STANDARD 20)

find_package(OpenSSL REQUIRED)
if(OPENSSL_FOUND)
    message(STATUS "OpenSSL found. Version: ${OPENSSL_VERSION}")
else()
    message(FATAL_ERROR "OpenSSL not found. Please install OpenSSL or provide the correct paths.")
endif()
add_subdirectory(tests)
