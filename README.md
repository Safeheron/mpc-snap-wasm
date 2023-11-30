# MPC-SNAP-WASM

# 1. Third_party说明

- 本项目通过submodule的方式，将依赖的第三方库和底层算法库引入。具体包含：

 - Openssl, 仓库地址：https://github.com/openssl/openssl
 - Protobuf, 仓库地址：https://github.com/protocolbuffers/protobuf
 - Safeheron CryptoSuites, 仓库地址：https://github.com/Safeheron/safeheron-crypto-suites-cpp
 - Safeheron mpc-flow-cpp, 长裤地址：https://github.com/Safeheron/mpc-flow-cpp
 - Safeheron multi-party-ecdsa, 仓库地址：https://github.com/Safeheron/multi-party-ecdsa-cpp

# 2. 编译说明

## 2.1 拉取submodule代码

```
  $ cd mpc-snap-wasm
  $ git submodule update --init --recursive
```

## 2.2 编译Openssl

- 使用OpenSSL_1_1_1-stable分支

```
  $ cd third_party/openssl
  $ cd openssl
  $ git checkout OpenSSL_1_1_1-stable
  $ cd ..
  $ ./build.sh
```
- 编译成功后，输出文件目录为：third_party/openssl/output

## 2.3 编译Protobuf

- 使用3.20.x分支

```
  $ cd third_party/protobuf
  $ cd protobuf
  $ git checkout 3.20.x
  $ cd ..
  $ ./build.sh
```
- 编译成功后，输出文件目录为：third_party/protobuf/output

## 2.4 编译CryptoSuites

- 使用stark_macro分支

```
  $ cd third_party/crypto-suites
  $ cd safeheron-crypto-suites-cpp
  $ git checkout stark_macro
  $ cd ..
  $ ./build.sh
```
- 编译成功后，输出文件目录为：third_party/crypto-suites/output

## 2.5 编译mpc-flow

- 使用main分支

```
  $ cd third_party/mpc-flow
  $ cd mpc-flow-cpp
  $ cd ..
  $ ./build.sh
```
- 编译成功后，输出文件目录为：third_party/mpc-flow/output

## multi-party-ecdsa

- 使用main分支

```
  $ cd third_party/multi-party-ecdsa
  $ cd multi-party-ecdsa-cpp
  $ cd ..
  $ ./build.sh
```
- 编译成功后，输出文件目录为：third_party/multi-party-ecdsa/output