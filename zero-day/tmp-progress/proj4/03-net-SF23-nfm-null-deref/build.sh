#!/usr/bin/env bash
# Build and run PoC: 03-net-SF23-nfm-null-deref
set -e
PROJ_SRC="${PROJ_SRC:-/src/PROJ-latest}"
PROJ_LIB="${PROJ_LIB:-/proj4-latest-build/lib/libproj.a}"
SQLITE="${SQLITE:-/usr/lib/x86_64-linux-gnu/libsqlite3.so.0}"
POC_BIN=/tmp/net_SF23_poc
echo "[*] Compiling PoC ..."
clang -std=c11 -fsanitize=address -fno-omit-frame-pointer -g -O1 \
    -I"$PROJ_SRC/src" \
    "$(dirname "$0")/net_SF23_poc.c" \
    "$PROJ_LIB" -lpthread "$SQLITE" -ldl -lm -lstdc++ \
    -o "$POC_BIN"
echo "[*] Running PoC ..."
ASAN_OPTIONS="halt_on_error=1:print_stacktrace=1:detect_leaks=0" \
    PROJ_DATA=/out/asan "$POC_BIN" 2>&1 || true
