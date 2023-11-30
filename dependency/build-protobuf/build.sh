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

emconfigure ./configure \
  --host=none-none-none  \
  --prefix=${PROTOBUF_OUTPUT_DIR}

#sed -i 's|^CROSS_COMPILE.*$|CROSS_COMPILE=|g' Makefile
#sed -i '/^CFLAGS/ s/$/ -D__STDC_NO_ATOMICS__=1/' Makefile
#sed -i '/^CXXFLAGS/ s/$/ -D__STDC_NO_ATOMICS__=1/' Makefile

emmake make -j8
make install

cd ..

echo "done"