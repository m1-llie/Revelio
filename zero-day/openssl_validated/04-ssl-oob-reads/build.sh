#!/usr/bin/env bash
# Compile and run all PoCs for 04-ssl-oob-reads
set -e
OPENSSL="${OPENSSL_SRC:-/tmp/openssl-latest}"
DIR="$(dirname "$0")"
ASAN_OPTIONS="halt_on_error=0:print_stacktrace=1:detect_leaks=0"
export ASAN_OPTIONS

if [ ! -f "$OPENSSL/libssl.a" ]; then
    echo "ERROR: $OPENSSL/libssl.a not found. Run ../build.sh first." >&2
    exit 1
fi

for poc in "$DIR"/*.c; do
    name=$(basename "$poc" .c)
    bin="/tmp/poc_$name"
    echo "[*] Compiling $name ..."
    clang -fsanitize=address,undefined -fno-omit-frame-pointer -g -O1 \
        -I"$OPENSSL/include" "$poc" \
        "$OPENSSL/libssl.a" "$OPENSSL/libcrypto.a" \
        -lpthread -ldl -o "$bin"
    echo "[*] Running $name ..."
    "$bin" 2>&1 || true
    echo ""
done
