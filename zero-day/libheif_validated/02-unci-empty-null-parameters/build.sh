#!/usr/bin/env bash
# Build latest libheif with ASAN+UBSan (WITH_UNCOMPRESSED_CODEC=ON) and run SF13 PoC.
# Requires: clang, cmake, make, git
# Usage: bash build.sh
set -e

WORKDIR="/tmp/libheif_sf13_build"
INSTALL_DIR="/tmp/libheif_sf13_inst"
POC_DIR="$(dirname "$0")"

echo "[1/4] Clone latest libheif master"
if [ ! -d "$WORKDIR/libheif" ]; then
    git clone --depth=1 https://github.com/strukturag/libheif.git "$WORKDIR/libheif"
fi
echo "Commit: $(git -C "$WORKDIR/libheif" log --oneline -1)"

echo "[2/4] Build with ASAN + UBSan + UNCOMPRESSED_CODEC"
mkdir -p "$WORKDIR/build" && cd "$WORKDIR/build"
CC=clang CXX=clang++ cmake "$WORKDIR/libheif" \
    -DCMAKE_BUILD_TYPE=Debug \
    -DCMAKE_INSTALL_PREFIX="$INSTALL_DIR" \
    -DCMAKE_C_FLAGS="-fsanitize=address,undefined -fno-omit-frame-pointer -g -O1" \
    -DCMAKE_CXX_FLAGS="-fsanitize=address,undefined -fno-omit-frame-pointer -g -O1" \
    -DCMAKE_EXE_LINKER_FLAGS="-fsanitize=address,undefined" \
    -DCMAKE_SHARED_LINKER_FLAGS="-fsanitize=address,undefined" \
    -DWITH_UNCOMPRESSED_CODEC=ON \
    -DWITH_LIBDE265=OFF -DWITH_X265=OFF -DWITH_JPEG_DECODER=OFF \
    -DWITH_JPEG_ENCODER=OFF -DBUILD_TESTING=OFF -DWITH_EXAMPLES=OFF
make -j"$(nproc)" install

echo "[3/4] Compile PoC"
clang++ -fsanitize=address,undefined -fno-omit-frame-pointer -g -O1 \
    -I"$INSTALL_DIR/include" \
    "$POC_DIR/poc_trigger.cc" \
    -L"$INSTALL_DIR/lib" -Wl,-rpath,"$INSTALL_DIR/lib" \
    -lheif -o /tmp/sf13_poc
echo "PoC binary: /tmp/sf13_poc"

echo "[4/4] Run PoC"
ASAN_OPTIONS="halt_on_error=0:print_stacktrace=1:detect_leaks=0" \
UBSAN_OPTIONS="print_stacktrace=1:halt_on_error=0" \
    /tmp/sf13_poc 2>&1 || true
