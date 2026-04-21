#!/usr/bin/env bash
# build.sh — Build libheif from source with ASAN, compile the POC, run it.
#
# Runs entirely inside Docker (docker run --rm vulagent/libheif:latest bash build.sh)
# or can be sourced manually inside the container.
#
# Usage (from host, POC files mounted at /poc):
#   docker run --rm \
#     -v /scr2/yiwei/vul-agent/zero-day/libheif_validated/08-track-release-double-free:/poc \
#     vulagent/libheif:latest bash /poc/build.sh

set -euo pipefail

SRC=/src/libheif
BUILD_DIR=/tmp/libheif_asan_build
INSTALL_DIR=/tmp/libheif_asan_install
POC_DIR=/poc

# ── Compiler / ASAN flags ────────────────────────────────────────────────────
export CC=clang
export CXX=clang++
export ASAN_FLAGS="-fsanitize=address,undefined -fno-omit-frame-pointer -g -O1"
export CFLAGS="$ASAN_FLAGS"
export CXXFLAGS="$ASAN_FLAGS"

echo "[1/5] Configuring libheif with ASAN (no codec plugins — minimal build)..."
rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR"
cd "$BUILD_DIR"

cmake "$SRC" \
  -DCMAKE_C_COMPILER="$CC" \
  -DCMAKE_CXX_COMPILER="$CXX" \
  -DCMAKE_C_FLAGS="$CFLAGS" \
  -DCMAKE_CXX_FLAGS="$CXXFLAGS" \
  -DCMAKE_BUILD_TYPE=Debug \
  -DCMAKE_INSTALL_PREFIX="$INSTALL_DIR" \
  -DBUILD_SHARED_LIBS=OFF \
  -DWITH_LIBDE265=OFF \
  -DWITH_X265=OFF \
  -DWITH_AOM_DECODER=OFF \
  -DWITH_AOM_ENCODER=OFF \
  -DWITH_DAV1D=OFF \
  -DWITH_SvtEnc=OFF \
  -DWITH_JPEG_DECODER=OFF \
  -DWITH_JPEG_ENCODER=OFF \
  -DWITH_OpenH264_DECODER=OFF \
  -DWITH_OpenJPEG_ENCODER=OFF \
  -DWITH_OpenJPEG_DECODER=OFF \
  -DWITH_OPENJPH_ENCODER=OFF \
  -DWITH_VVDEC=OFF \
  -DWITH_VVENC=OFF \
  -DWITH_UNCOMPRESSED_CODEC=OFF \
  -DBUILD_TESTING=OFF \
  -DWITH_EXAMPLES=OFF \
  2>&1 | tail -20

echo "[2/5] Building libheif (static, ASAN)..."
make -j"$(nproc)" heif 2>&1 | tail -10

echo "[3/5] Installing headers + library..."
make install 2>&1 | tail -5

echo "[4/5] Generating minimal HEIF sequence file..."
cd "$POC_DIR"
python3 gen_heif.py minimal_sequence.heif

echo "[5/5] Compiling and running POC with ASAN..."
clang++ $ASAN_FLAGS \
  -I"$INSTALL_DIR/include" \
  -I"$SRC/libheif/api" \
  poc_trigger.cc \
  "$INSTALL_DIR/lib/libheif.a" \
  -lpthread -ldl \
  -o poc_trigger

echo ""
echo "=== Running POC (ASAN output follows) ==="
ASAN_OPTIONS="halt_on_error=1:detect_leaks=0" \
  ./poc_trigger minimal_sequence.heif 2>&1 || true
echo "=== End of POC output ==="
