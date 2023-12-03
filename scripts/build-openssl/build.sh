#!/bin/sh

OPENSSL_SRC_DIR=${PWD}/../../third_party/openssl
echo "OPENSSL_SRC_DIR: ${OPENSSL_SRC_DIR}"

OPENSSL_OUTPUT_DIR=${PWD}/../
echo "OPENSSL_OUTPUT_DIR: ${OPENSSL_OUTPUT_DIR}"

cd $OPENSSL_SRC_DIR || exit 1

# Make the binary files reproducible
export SOURCE_DATE_EPOCH=1700815048

make clean

# !!!Must set platform as 'linux-x86'.
# !!!If set platform as 'linux-generic64', 
# !!!openssl will crash in bn_div_words() with shift operations.
emconfigure ./Configure \
  linux-x86 \
  no-asm \
  no-engine \
  no-threads \
  no-dso \
  no-tests \
  no-shared \
  --cross-compile-prefix="" \
  --prefix=$OPENSSL_OUTPUT_DIR

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

make install_sw

if [ $? -eq 0 ]; then
    echo "================> make install SUCCESS"
else
    echo "================> make install ERROR"
fi

echo "================> build openssl done"
