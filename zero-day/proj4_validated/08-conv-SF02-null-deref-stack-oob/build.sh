#!/usr/bin/env bash
# Build and run PoC: 08-conv-SF02-null-deref-stack-oob
set -e
PROJ_SRC="${PROJ_SRC:-/src/PROJ-latest}"
PROJ_LIB="${PROJ_LIB:-/proj4-latest-build/lib/libproj.a}"
SQLITE="${SQLITE:-/usr/lib/x86_64-linux-gnu/libsqlite3.so.0}"
POC_BIN=/tmp/conv_SF02_poc
echo "[*] Compiling PoC ..."
clang++ -std=c++17 -fsanitize=address -fno-omit-frame-pointer -g -O1 \
    -I"$PROJ_SRC/src" -I"$PROJ_SRC/include" \
    "$(dirname "$0")/conv_SF02_poc.cpp" \
    "$PROJ_LIB" -lpthread "$SQLITE" -ldl -lm \
    -o "$POC_BIN"
echo "[*] Running PoC ..."
ASAN_OPTIONS="halt_on_error=1:print_stacktrace=1:detect_leaks=0" \
    PROJ_DATA=/out/asan "$POC_BIN" 2>&1 || true
