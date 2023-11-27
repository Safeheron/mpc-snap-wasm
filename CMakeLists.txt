cmake_minimum_required(VERSION 3.16)
project("metamaskWASM" C CXX)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_EXECUTABLE_SUFFIX ".html")

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O3 -fPIC -Wall -Wextra -Wno-unused-parameter -Wno-unused-variable")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O3 -fPIC -Wall -Wextra -Wno-unused-parameter -Wno-unused-variable")

# Set path and file name for openssl
set(OPENSSL_ROOT /usr/local/safeheron/openssl/wasm)
set(OPENSSL_INCLUDE ${OPENSSL_ROOT}/include)
set(OPENSSL_LIB_FILE ${OPENSSL_ROOT}/lib/libcrypto.a)
set(OPENSSL_SSL_FILE ${OPENSSL_ROOT}/lib/libssl.a)

# Set path and file name for protobuf
set(PROTOBUF_ROOT /usr/local/safeheron/protobuf/wasm)
set(PROTOBUF_INCLUDE ${PROTOBUF_ROOT}/include)
set(PROTOBUF_LIB_FILE ${PROTOBUF_ROOT}/lib/libprotobuf.a)

# Set path and file name for Safeheron-Crypto-Suites
set(CRYPTO_SUIT_ROOT /usr/local/safeheron/crypto-suites/wasm)
set(CRYPTO_SUIT_INCLUDE ${CRYPTO_SUIT_ROOT}/include)
set(CRYPTO_SUIT_LIB_FILE ${CRYPTO_SUIT_ROOT}/lib/libSafeheronCryptoSuites.a)

# Set path and file name for Safeheron-Multi-Party-Signature
set(MULTI_SIGNATURE_ROOT /usr/local/safeheron/multi-party-signature/wasm)
set(MULTI_SIGNATURE_INCLUDE ${MULTI_SIGNATURE_ROOT}/include)
set(MULTI_SIGNATURE_LIB_FILE ${MULTI_SIGNATURE_ROOT}/lib/libSafeheronMultiPartySignature.a)

add_executable(
    ${CMAKE_PROJECT_NAME}

    src/common/tools.cpp
    src/common/thread_safe_pointer_container.cpp
    src/common/global_variables.cpp

    src/key_gen.cpp
    src/minimal_key_gen.cpp
    src/key_recovery.cpp
    src/aux_info_key_refresh.cpp
    src/sign.cpp
    src/util.cpp

    src/params/aux_info_key_refresh_context_param.cpp
    src/params/exchange_message_param.cpp
    src/params/key_gen_context_param.cpp
    src/params/minimal_key_gen_context_param.cpp
    src/params/key_recovery_context_param.cpp
    src/params/sign_context_param.cpp
    src/params/minimal_key_param.cpp
)

target_include_directories(${CMAKE_PROJECT_NAME} PUBLIC
    ${CMAKE_SOURCE_DIR}
    ${MULTI_SIGNATURE_INCLUDE}
    ${CRYPTO_SUIT_INCLUDE}
    ${PROTOBUF_INCLUDE}
    ${OPENSSL_INCLUDE}
    ${MULTI_SIGNATURE_INCLUDE}/safeheron
    ${CRYPTO_SUIT_INCLUDE}/safeheron
    third_party/ #current directory
    #emsdk directory
)

target_link_libraries(${CMAKE_PROJECT_NAME} PRIVATE
    ${CRYPTO_SUIT_LIB_FILE}
    ${MULTI_SIGNATURE_LIB_FILE}
    ${PROTOBUF_LIB_FILE}
    ${OPENSSL_LIB_FILE}
)

# Set exported functions name
set_target_properties(${CMAKE_PROJECT_NAME} PROPERTIES LINK_FLAGS "\
    -s ENVIRONMENT='web' \
    -s FILESYSTEM=1 \
    -s MODULARIZE=1 \
    -s INVOKE_RUN=0 \
    -s EXIT_RUNTIME=1 \
    -s EXPORT_ES6=1 \
    -s ASSERTIONS=1 \
    -s TOTAL_MEMORY=33554432 \
    -s USE_ES6_IMPORT_META=0 \
    -s ALLOW_MEMORY_GROWTH=1 \
    -s NO_DISABLE_EXCEPTION_CATCHING \
    -s EXPORT_ALL=1 \
    -s EXPORTED_RUNTIME_METHODS=\"['cwrap', 'ccall']\" \
    -s EXPORTED_FUNCTIONS=\"['_malloc','_free']\" \
")
