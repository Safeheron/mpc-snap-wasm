#!/bin/bash

# build path
BUILD_DIR=${PWD}/build
if [ -d "$BUILD_DIR" ]; then
    rm -rf "$BUILD_DIR"
fi		
mkdir -p $BUILD_DIR
echo "Build path: $BUILD_DIR"

cd $BUILD_DIR

emcmake cmake ..
if [ $? -eq 0 ]; then
    echo "================> emcmake cmake SUCCESS"
else
    echo "================> emcmake cmake ERROR"
    exit 1
fi

emmake make -j$(nproc)
if [ $? -eq 0 ]; then
    echo "================> emcmake make SUCCESS"
else
    echo "================> emcmake make ERROR"
    exit 1
fi
