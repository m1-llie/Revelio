#!/usr/bin/env bash
# Compile and run PoC 01: null ctx in SSL_CTX_use_PrivateKey()
# Builds OpenSSL from /src/openssl with ASAN/UBSAN if not already built.
# Usage: bash build.sh
set -e

OPENSSL_SRC="/src/openssl"
POC_BIN="/tmp/poc01"

# ── 1. Build OpenSSL with ASAN/UBSAN if not already built ─────────────────
if [ ! -f "$OPENSSL_SRC/libssl.a" ]; then
    echo "[*] Configuring OpenSSL ..."
    cd "$OPENSSL_SRC"
    ./config no-shared no-tests no-apps --debug \
        CC=clang -fsanitize=address,undefined -fno-omit-frame-pointer -g -O1
    echo "[*] Building libraries ..."
    make -j"$(nproc)" build_libs
fi

# ── 2. Compile PoC ─────────────────────────────────────────────────────────
echo "[*] Compiling PoC ..."
clang -fsanitize=address,undefined -fno-omit-frame-pointer -g -O1 \
    -I"$OPENSSL_SRC/include" \
    "$(dirname "$0")/01-SSL_CTX_use_PrivateKey-null-ctx.c" \
    "$OPENSSL_SRC/libssl.a" "$OPENSSL_SRC/libcrypto.a" \
    -lpthread -ldl -o "$POC_BIN"

# ── 3. Run ─────────────────────────────────────────────────────────────────
echo "[*] Running PoC ..."
ASAN_OPTIONS="halt_on_error=1:print_stacktrace=1:detect_leaks=0" "$POC_BIN" 2>&1 || true
