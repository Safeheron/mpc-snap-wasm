#!/bin/bash
OPENSSL_ROOT=$1
PROTOBUF_ROOT=$2
CRYPTOSUITES_ROOT=$3
MULTI_SIGNATURE_ROOT=$4
PREFIX_PATH=$5

set -u

# install path
if [ x"$PREFIX_PATH" = x"" ]; then
    PREFIX_PATH=${PWD}/output
fi
if [ -d "$PREFIX_PATH" ]; then
    rm -rf "$PREFIX_PATH"
fi		
mkdir -p $PREFIX_PATH
echo "Install path: $PREFIX_PATH"

# openssl and protobuf path
if [ x"$OPENSSL_ROOT" = x"" ]; then
    OPENSSL_ROOT=/usr/local/safeheron/openssl/wasm
fi
if [ x"$PROTOBUF_ROOT" = x"" ]; then
    PROTOBUF_ROOT=/usr/local/safeheron/protobuf/wasm
fi
if [ x"$CRYPTOSUITES_ROOT" = x"" ]; then
    CRYPTOSUITES_ROOT=/usr/local/safeheron/crypto-suites/wasm
fi
if [ x"$MULTI_SIGNATURE_ROOT" = x"" ]; then
    MULTI_SIGNATURE_ROOT=/usr/local/safeheron/multi-party-signature/wasm
fi
echo "Openssl path: $OPENSSL_ROOT"
echo "Protobuf path: $PROTOBUF_ROOT"
echo "CryptoSuites path: $CRYPTOSUITES_ROOT"
echo "MultiPartySignature path: $MULTI_SIGNATURE_ROOT"

# build path
BUILD_DIR=${PWD}/build
if [ -d "$BUILD_DIR" ]; then
    rm -rf "$BUILD_DIR"
fi		
mkdir -p $BUILD_DIR
echo "Build path: $BUILD_DIR"

cd $BUILD_DIR

emcmake cmake ..
emmake make -j 8

# cd ..
# rm -rf "$BUILD_DIR"

echo "done"
