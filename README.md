# MPC-SNAP-WASM

## 1. 安装依赖

- 安装Python 2.7.12或更新版

## 2. 安装emscripten

### 2.1 下载emsdk

```
    # 获取emsdk包
    $ git clone https://github.com/emscripten-core/emsdk.git
 
    # 进入文件夹
    $ cd emsdk
```

### 2.2 安装与激活

- 运行以下的emsdk指令去从Github获取最新的工具并激活工具

```
    # 获取最新的emsdk版本
    $ git pull
 
    # 下载和安装最新的工具（需要科学上网）
    $ ./emsdk install latest
 
    # 激活工具
    $ ./emsdk activate latest
 
    # 激活环境变量（需设置环境变量，会有提示的）
    $ source ./emsdk_env.sh
```
- 检查是否安装成功

```
    $ emcc -v
```
- 若能显示emsdk的版本信息，则说明安装成功！

## 3. Third_party说明

- 本项目通过submodule的方式，将依赖的第三方库和底层算法库引入。具体包含：

 - Openssl, 仓库地址：https://github.com/openssl/openssl
 - Protobuf, 仓库地址：https://github.com/protocolbuffers/protobuf
 - Safeheron CryptoSuites, 仓库地址：https://github.com/Safeheron/safeheron-crypto-suites-cpp
 - Safeheron multi-party-ecdsa, 仓库地址：https://github.com/Safeheron/multi-party-ecdsa-cpp

## 4. 编译说明

### 4.1 拉取submodule代码

```
  $ cd mpc-snap-wasm
  $ git submodule update --init --recursive
```

### 4.2 编译Openssl

- 使用OpenSSL_1_1_1-stable分支

```
  $ cd third_party/openssl
  $ cd openssl
  $ git checkout OpenSSL_1_1_1-stable
  $ cd ../../dependency/build-opnessl
  $ ./build.sh
```
- 编译成功后，输出文件目录为：dependency/include 和 dependency/lib

### 4.3 编译Protobuf

- 使用3.20.x分支

```
  $ cd third_party/protobuf
  $ cd protobuf
  $ git checkout 3.20.x
  $ cd ../../dependency/build-protobuf
  $ ./build.sh
```
- 编译成功后，输出文件目录为：dependency/include 和 dependency/lib

### 4.4 编译CryptoSuites

- 使用main分支

```
  $ cd dependency/build-crypto-suites
  $ ./build.sh
```
- 编译成功后，输出文件目录为：dependency/include 和 dependency/lib

### 4.5 multi-party-ecdsa

- 使用main分支

```
  $ cd dependency/build-multi-party-sig
  $ ./build.sh
```
- 编译成功后，输出文件目录为：dependency/include 和 dependency/lib