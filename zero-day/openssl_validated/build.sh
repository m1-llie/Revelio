#!/usr/bin/env bash
# Build OpenSSL 4.1.0-dev from a fresh clone with ASAN+UBSAN.
# Usage: bash build.sh [/path/to/clone/dir]
set -e

DEST="${1:-/tmp/openssl-latest}"

if [ ! -d "$DEST" ]; then
    echo "[*] Cloning OpenSSL master ..."
    git clone --depth=1 https://github.com/openssl/openssl.git "$DEST"
fi

if [ ! -f "$DEST/libssl.a" ]; then
    echo "[*] Configuring with ASAN+UBSAN ..."
    cd "$DEST"
    ./config no-shared no-tests no-apps --debug \
        CC=clang \
        CFLAGS="-fsanitize=address,undefined -fno-omit-frame-pointer -g -O1"
    echo "[*] Building libraries ($(nproc) jobs) ..."
    make -j"$(nproc)" build_libs
    echo "[*] Build complete: $DEST/libssl.a $DEST/libcrypto.a"
else
    echo "[*] Using existing build: $DEST"
fi

echo "OPENSSL_SRC=$DEST"
