#!/bin/bash
OPENSSL_ROOT=$1
PROTOBUF_ROOT=$2
PREFIX_PATH=$3

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
    OPENSSL_ROOT=${PWD}/../openssl/output
fi
if [ x"$PROTOBUF_ROOT" = x"" ]; then
    PROTOBUF_ROOT=${PWD}/../protobuf/output
fi
echo "Openssl path: $OPENSSL_ROOT"
echo "Protobuf path: $PROTOBUF_ROOT"

# build path
BUILD_DIR=${PWD}/build
if [ -d "$BUILD_DIR" ]; then
    rm -rf "$BUILD_DIR"
fi		
mkdir -p $BUILD_DIR
echo "Build path: $BUILD_DIR"

cd $BUILD_DIR

emcmake cmake .. \
	-DCMAKE_INSTALL_PREFIX=$PREFIX_PATH \
	-DOPENSSL_ROOT=$OPENSSL_ROOT \
	-DPROTOBUF_ROOT=$PROTOBUF_ROOT

cmake --build . -- -j8

make install

rm -rf "$BUILD_DIR"

echo "done"