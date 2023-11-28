#!/bin/bash
OPENSSL_ROOT=$1
PROTOBUF_ROOT=$2
CRYPTOSUITES_ROOT=$3
PREFIX_PATH=$4

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
echo "Openssl path: $OPENSSL_ROOT"
echo "Protobuf path: $PROTOBUF_ROOT"
echo "CryptoSuites path: $CRYPTOSUITES_ROOT"

# build path
BUILD_DIR=${PWD}/build
if [ -d "$BUILD_DIR" ]; then
    rm -rf "$BUILD_DIR"
fi		
mkdir -p $BUILD_DIR
echo "Build path: $BUILD_DIR"

cd $BUILD_DIR

# You can use below macros to disable special module(s)
#    -DNO_MPC_GG18=ON
#    -DNO_MPC_GG18_HD=ON
#    -DNO_MPC_GG18_HD_V0=ON
#    -DNO_MPC_GG20=ON
#    -DNO_MPC_GG20_HD=ON
#    -DNO_MPC_GG20_ENHANCE=ON
#    -DNO_MPC_CMP=ON
#    -DNO_MPC_CMP_N_N=ON
#    -DNO_EDDSA_R4=ON
#    -DNO_EDDSA_R4_V0=ON
emcmake cmake .. \
	-DCMAKE_INSTALL_PREFIX=$PREFIX_PATH \
	-DOPENSSL_ROOT=$OPENSSL_ROOT \
	-DPROTOBUF_ROOT=$PROTOBUF_ROOT \
    -DCRYPTOSUITES_ROOT=$CRYPTOSUITES_ROOT 

cmake --build . -- -j8

make install

rm -rf "$BUILD_DIR"

echo "done"