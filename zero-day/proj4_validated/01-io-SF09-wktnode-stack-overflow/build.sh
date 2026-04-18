#!/usr/bin/env bash
# Build and run PoC 01: WKTNode::toString() unbounded recursion (stack overflow)
# Requires: vulagent/proj4-asan Docker image, latest PROJ source at /src/PROJ-latest
set -e

PROJ_SRC="${PROJ_SRC:-/src/PROJ-latest}"
PROJ_LIB="${PROJ_LIB:-/proj4-latest-build/lib/libproj.a}"
SQLITE="${SQLITE:-/usr/lib/x86_64-linux-gnu/libsqlite3.so.0}"
POC_BIN=/tmp/poc_01_io_sf09

echo "[*] Compiling PoC ..."
clang++ -std=c++17 -DFROM_PROJ_CPP -fsanitize=address -g -O1 \
    -I"$PROJ_SRC/src" -I"$PROJ_SRC/include" \
    "$(dirname "$0")/io_SF09_poc.cpp" \
    "$PROJ_LIB" \
    -lpthread "$SQLITE" -ldl -lm \
    -o "$POC_BIN"

echo "[*] Running PoC ..."
ASAN_OPTIONS="halt_on_error=1:print_stacktrace=1:detect_leaks=0" \
    PROJ_DATA=/out/asan "$POC_BIN" 2>&1 || true
