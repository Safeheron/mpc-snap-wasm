cmake_minimum_required(VERSION 3.16)
project("MultiPartyEcdsa" VERSION 1.4.0 LANGUAGES C CXX)
 
set(CMAKE_CXX_STANDARD 11)
SET(CMAKE_BUILD_TYPE "Release")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O3 -fPIC -Wall -Wextra -Wno-unused-parameter -Wno-unused-variable")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O3 -fPIC -Wall -Wextra -Wno-unused-parameter -Wno-unused-variable")

cmake_policy(SET CMP0076 NEW)
cmake_policy(SET CMP0077 NEW)
cmake_policy(SET CMP0079 NEW)

message(STATUS "OPENSSL_ROOT=${OPENSSL_ROOT}")
message(STATUS "PROTOBUF_ROOT=${PROTOBUF_ROOT}")
message(STATUS "CRYPTOSUITES_ROOT=${CRYPTOSUITES_ROOT}")

# Build shared or static 
if(${ENABLE_SHARED})
    message(STATUS "Don't support to build shared library!")
else()
    message(STATUS "Build static library!")
    add_library(${CMAKE_PROJECT_NAME} STATIC "")
    install(FILES ${CMAKE_CURRENT_BINARY_DIR}/lib${CMAKE_PROJECT_NAME}.a
        DESTINATION lib/${ARCHS}
        PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ
    )    
endif()

add_subdirectory(${CMAKE_SOURCE_DIR}/multi-party-sig-cpp/src/multi-party-sig/mpc-flow)
add_subdirectory(${CMAKE_SOURCE_DIR}/multi-party-sig-cpp/src/multi-party-sig/multi-party-ecdsa)

option(ENABLE_SNAP_SCOPE "Enable Snap Scope" OFF)
if (${ENABLE_SNAP_SCOPE})
    message(STATUS "Notice: ******************* Enable Snap Scope ******************* ")
endif()

# Set include path
target_include_directories(${CMAKE_PROJECT_NAME} PRIVATE
    ${CMAKE_SOURCE_DIR}/multi-party-sig-cpp/src
    ${OPENSSL_ROOT}/include
    ${PROTOBUF_ROOT}/include
    ${CRYPTOSUITES_ROOT}/include
)

# Install header files
install(
        DIRECTORY
            ${CMAKE_SOURCE_DIR}/multi-party-sig-cpp/src/multi-party-sig
        DESTINATION include
        FILES_MATCHING PATTERN "*.h"
)
