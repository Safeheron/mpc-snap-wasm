cmake_minimum_required(VERSION 3.16)
project("SafeheronCryptoSuites" VERSION 1.4.0 LANGUAGES C CXX)
 
set(CMAKE_CXX_STANDARD 11)
SET(CMAKE_BUILD_TYPE "Release")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O3 -fPIC -Wall -Wextra -Wno-unused-parameter -Wno-unused-variable")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O3 -fPIC -Wall -Wextra -Wno-unused-parameter -Wno-unused-variable")

cmake_policy(SET CMP0076 NEW)
cmake_policy(SET CMP0077 NEW)
cmake_policy(SET CMP0079 NEW)

message(STATUS "OPENSSL_ROOT=${OPENSSL_ROOT}")
message(STATUS "PROTOBUF_ROOT=${PROTOBUF_ROOT}")

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

# Set the source file path
set(CRYPTO_SUITES_SOURCE_PATH ${CMAKE_SOURCE_DIR}/safeheron-crypto-suites-cpp/src)
message(STATUS "CRYPTO_SUITES_SOURCE_PATH=${CRYPTO_SUITES_SOURCE_PATH}")

add_subdirectory(${CRYPTO_SUITES_SOURCE_PATH})

# Set include path
target_include_directories(${CMAKE_PROJECT_NAME} PRIVATE
    ${CRYPTO_SUITES_SOURCE_PATH}
    ${OPENSSL_ROOT}/include
    ${PROTOBUF_ROOT}/include
)

## Install head files
install(
        DIRECTORY
            ${CRYPTO_SUITES_SOURCE_PATH}/crypto-suites
        DESTINATION include
        FILES_MATCHING PATTERN "*.h"

        # crypto-bip32-cpp
        PATTERN "ed25519_ex.h" EXCLUDE
        PATTERN "openssl_curve_wrapper.h" EXCLUDE
        PATTERN "util.h" EXCLUDE
        PATTERN "memzero.h" EXCLUDE
        PATTERN "bip32_ed25519.h" EXCLUDE
        PATTERN "bip32_ecdsa.h" EXCLUDE

        # crypto-curve-cpp
        PATTERN "ed25519_ex.h" EXCLUDE
        PATTERN "openssl_curve_wrapper.h" EXCLUDE

        # crypto-encode-cpp
        PATTERN "base64_imp.h" EXCLUDE
        PATTERN "hex_imp.h" EXCLUDE
        PATTERN "base58_imp.h" EXCLUDE

        # crypto-hash-cpp
        PATTERN "compat.h" EXCLUDE

        # crypto-ecies-cpp
        PATTERN "hmac.h" EXCLUDE
        PATTERN "kdf.h" EXCLUDE
        PATTERN "symm.h" EXCLUDE
)
