#!/usr/bin/env bash
# Build and run PoC: 09-grids-SF01-proj-grid-info-null
set -e
PROJ_SRC="${PROJ_SRC:-/src/PROJ-latest}"
PROJ_LIB="${PROJ_LIB:-/proj4-latest-build/lib/libproj.a}"
SQLITE="${SQLITE:-/usr/lib/x86_64-linux-gnu/libsqlite3.so.0}"
POC_BIN=/tmp/grids_SF01_poc
echo "[*] Compiling PoC ..."
clang++ -std=c++17 -fsanitize=address -fno-omit-frame-pointer -g -O1 \
    -I"$PROJ_SRC/src" -I"$PROJ_SRC/include" \
    "$(dirname "$0")/grids_SF01_poc.cpp" \
    "$PROJ_LIB" -lpthread "$SQLITE" -ldl -lm \
    -o "$POC_BIN"
echo "[*] Running PoC ..."
ASAN_OPTIONS="halt_on_error=1:print_stacktrace=1:detect_leaks=0" \
    PROJ_DATA=/out/asan "$POC_BIN" 2>&1 || true
