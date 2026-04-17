#!/usr/bin/env bash
# Build and run the SF06 PoC inside vulagent/openssl:latest
set -e

OPENSSL_SRC="/src/openssl33"
POC_C="/tmp/sf06_poc.c"
POC_BIN="/tmp/sf06_poc"

if [ ! -f "$OPENSSL_SRC/libssl.a" ]; then
    echo "[*] Configuring openssl33 ..."
    cd "$OPENSSL_SRC"
    ./config no-shared no-tests no-apps --debug \
        -fsanitize=address,undefined -fno-omit-frame-pointer -g -O1
    echo "[*] Building libraries ..."
    make -j"$(nproc)" build_libs
fi

echo "[*] Compiling PoC ..."
clang -fsanitize=address,undefined -fno-omit-frame-pointer -g -O1 \
    -I"$OPENSSL_SRC/include" \
    "$POC_C" \
    "$OPENSSL_SRC/libssl.a" "$OPENSSL_SRC/libcrypto.a" \
    -lpthread -ldl -o "$POC_BIN"

echo "[*] Running PoC ..."
ASAN_OPTIONS="halt_on_error=1:print_stacktrace=1:detect_leaks=0" "$POC_BIN" 2>&1 || true
