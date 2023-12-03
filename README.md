# MPC-SNAP-WASM

## Build

- Clone this repository and update submodule:

```bash
git submodule update --init --recursive
```

- Install Docker

### Build docker image

This docker image is used to build all source codes.

```bash
cd scripts/build-docker-image
bash build.sh
```

### Build deps & WASM

To build the final WASM file, its dependencies must be built in order: OpenSSL, Protobuf, Crypto-Suites and Multi-Party-Sig. Finally, build the WASM file.

Run the following command in this repository root folder.

- Build OpenSSL

```bash
docker run --rm -v $(pwd):/src -u $(id -u):$(id -g) wasm-build:1.0.0 bash -c 'cd /src/scripts/build-openssl && ./build.sh'
```

- Build Protobuf

```bash
docker run --rm -v $(pwd):/src -u $(id -u):$(id -g) wasm-build:1.0.0 bash -c 'cd /src/scripts/build-protobuf && ./build.sh'
```

- Build Crypto-Suites

```bash
docker run --rm -v $(pwd):/src -u $(id -u):$(id -g) wasm-build:1.0.0 bash -c 'cd /src/scripts/build-crypto-suites && ./build.sh'
```

- Build Multi-Party-Sig

```bash
docker run --rm -v $(pwd):/src -u $(id -u):$(id -g) wasm-build:1.0.0 bash -c 'cd /src/scripts/build-multi-party-sig && ./build.sh'
```

- Build MPC SNAP WASM

```bash
docker run --rm -v $(pwd):/src -u $(id -u):$(id -g) wasm-build:1.0.0 /src/build.sh
```

The WASM file will be output to the `build` folder.
