cmake_minimum_required(VERSION 3.10)

# set the project name
project(netpune)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED true)
set_property(TARGET ${TARGET_NAME} PROPERTY CXX_STANDARD 20)

# include folders
FILE(GLOB_RECURSE MY_HEADERS "../*.h*")

# add the executable
if(MSVC)
   include_directories(../ ./ ${OPENSSL_INCLUDE_DIR})
   add_executable(netpune rmunit.cpp netpune-ut.cpp ../wepoll.c ${MY_HEADERS} )
else()
   include_directories(../ ./ ${OPENSSL_INCLUDE_DIR})
   add_executable(netpune rmunit.cpp netpune.cpp )
endif()

target_link_libraries(netpune ${OPENSSL_LIBRARIES})
