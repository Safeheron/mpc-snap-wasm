#!/bin/sh

PROTOBUF_SRC_DIR=${PWD}/../../third_party/protobuf
echo "PROTOBUF_SRC_DIR: ${PROTOBUF_SRC_DIR}"

PROTOBUF_OUTPUT_DIR=${PWD}/../
echo "PROTOBUF_OUTPUT_DIR: ${PROTOBUF_OUTPUT_DIR}"

cd $PROTOBUF_SRC_DIR || exit 1

### ax_pthread.m4 will cause protobuf to use pthread automatically.
### However, some browsers don't support pthread for wasm yet.
### So we have no choices but just remove this file by hard code here
mv ./m4/ax_pthread.m4 ./m4/ax_pthread.m4-del

make clean

./autogen.sh
if [ $? -eq 0 ]; then
    echo "================> autogen SUCCESS"
else
    echo "================> autogen ERROR"
    exit 1
fi

emconfigure ./configure \
  --host=none-none-none  \
  --prefix=${PROTOBUF_OUTPUT_DIR}
if [ $? -eq 0 ]; then
    echo "================> emconfigure SUCCESS"
else
    echo "================> emconfigure ERROR"
    exit 1
fi

emmake make -j$(nproc)
if [ $? -eq 0 ]; then
    echo "================> emmake SUCCESS"
else
    echo "================> emmake ERROR"
    exit 1
fi

make install
if [ $? -eq 0 ]; then
    echo "================> make install SUCCESS"
else
    echo "================> make install ERROR"
fi

echo "================> build protobug done"
