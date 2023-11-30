#!/bin/bash
OPENSSL_ROOT=$1
PROTOBUF_ROOT=$2
PREFIX_PATH=$3

set -u

# install path
if [ x"$PREFIX_PATH" = x"" ]; then
    PREFIX_PATH=${PWD}/../
fi
if [ -d "$PREFIX_PATH" ]; then
    rm -rf "$PREFIX_PATH"
fi		
mkdir -p $PREFIX_PATH
echo "Install path: $PREFIX_PATH"

# openssl and protobuf path
if [ x"$OPENSSL_ROOT" = x"" ]; then
    OPENSSL_ROOT=${PWD}/../
fi
if [ x"$PROTOBUF_ROOT" = x"" ]; then
    PROTOBUF_ROOT=${PWD}/../
fi
echo "Openssl path: $OPENSSL_ROOT"
echo "Protobuf path: $PROTOBUF_ROOT"

# link source code paths
target_src_symbol=$(pwd)/safeheron-crypto-suites-cpp
ln -s $(pwd)/../../third_party/safeheron-crypto-suites-cpp $target_src_symbol

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
	-DPROTOBUF_ROOT=$PROTOBUF_ROOT \
    -DENABLE_SNAP_SCOPE=ON

cmake --build . -- -j8

make install

rm -rf $target_src_symbol
rm -rf "$BUILD_DIR"

echo "done"