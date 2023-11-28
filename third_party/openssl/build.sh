#!/bin/sh

OPENSSL_SRC_DIR=${PWD}/openssl
echo "OPENSSL_SRC_DIR: ${OPENSSL_SRC_DIR}"

OPENSSL_OUTPUT_DIR=${PWD}/output
echo "OPENSSL_OUTPUT_DIR: ${OPENSSL_OUTPUT_DIR}"

cd $OPENSSL_SRC_DIR || exit 1

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
  --cross-compile-prefix="" \
  --prefix=$OPENSSL_OUTPUT_DIR

#sed -i 's|^CROSS_COMPILE.*$|CROSS_COMPILE=|g' Makefile
#sed -i '/^CFLAGS/ s/$/ -D__STDC_NO_ATOMICS__=1/' Makefile
#sed -i '/^CXXFLAGS/ s/$/ -D__STDC_NO_ATOMICS__=1/' Makefile

emmake make -j 4 build_generated libssl.a libcrypto.a

make install

cd ..

echo "done"