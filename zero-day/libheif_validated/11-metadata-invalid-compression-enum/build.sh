#!/bin/bash
# Build and run script for Bug 11 POC: Invalid heif_metadata_compression enum
#
# Requires: docker image vulagent/libheif:latest
# Output:   ubsan_output_validated.txt (in same directory)
#
# Expected: 8 UBSan "load of value 99, which is not a valid value for type
#           'heif_metadata_compression'" errors at context.cc:1728/1762/1767/1774/1783
#           and heif_metadata.cc:204.

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
POC_SRC="${SCRIPT_DIR}/poc_trigger.cc"
OUT_LOG="${SCRIPT_DIR}/ubsan_output_validated.txt"

echo "[*] Building libheif from source with ASAN+UBSan and running POC..."
echo "[*] This will take ~1-2 minutes (compiling libheif)."

docker run --rm \
  -v "${SCRIPT_DIR}:/poc" \
  -e ASAN_OPTIONS="detect_leaks=0:halt_on_error=0" \
  -e UBSAN_OPTIONS="print_stacktrace=1:halt_on_error=0" \
  vulagent/libheif:latest \
  bash -c '
    set -e
    SRC_DIR=/src/libheif
    BUILD_DIR=/tmp/heif_build_bug11
    POC_DIR=/poc

    echo "[*] Configuring libheif with ASAN+UBSan..."
    mkdir -p "$BUILD_DIR"
    cd "$BUILD_DIR"

    cmake "$SRC_DIR" \
      -DCMAKE_C_COMPILER=clang \
      -DCMAKE_CXX_COMPILER=clang++ \
      -DCMAKE_BUILD_TYPE=Debug \
      -DCMAKE_C_FLAGS="-fsanitize=address,undefined -fno-omit-frame-pointer -g" \
      -DCMAKE_CXX_FLAGS="-fsanitize=address,undefined -fno-omit-frame-pointer -g" \
      -DCMAKE_EXE_LINKER_FLAGS="-fsanitize=address,undefined" \
      -DBUILD_SHARED_LIBS=OFF \
      -DWITH_UNCOMPRESSED_CODEC=ON \
      -DWITH_EXAMPLES=OFF \
      -DWITH_FUZZERS=OFF \
      -DWITH_REDUCED_VISIBILITY=OFF \
      2>&1 | tail -5

    echo "[*] Building libheif static library..."
    make -j$(nproc) heif 2>&1 | tail -5

    # Create linker symlinks for versioned .so files lacking a plain .so symlink
    ln -sf /lib/x86_64-linux-gnu/libz.so.1 /tmp/libz.so
    ln -sf /usr/lib/x86_64-linux-gnu/libbrotlidec.so.1 /tmp/libbrotlidec.so
    ln -sf /usr/lib/x86_64-linux-gnu/libbrotlienc.so.1 /tmp/libbrotlienc.so
    ln -sf /usr/lib/x86_64-linux-gnu/libbrotlicommon.so.1 /tmp/libbrotlicommon.so

    echo "[*] Compiling POC..."
    # Note: $BUILD_DIR on include path provides cmake-generated heif_version.h
    #       (included as <libheif/heif_version.h>, lives at $BUILD_DIR/libheif/heif_version.h)
    clang++ \
      -fsanitize=address,undefined \
      -fno-omit-frame-pointer \
      -g \
      -std=c++17 \
      -I "$SRC_DIR/libheif/api" \
      -I "$SRC_DIR/libheif" \
      -I "$BUILD_DIR" \
      "$POC_DIR/poc_trigger.cc" \
      -o /tmp/poc11_trigger \
      "$BUILD_DIR/libheif/libheif.a" \
      -L /tmp \
      -lz -lbrotlidec -lbrotlienc -lbrotlicommon \
      2>&1

    echo "[*] Running POC (UBSan output follows)..."
    /tmp/poc11_trigger 2>&1
  ' 2>&1 | tee "${OUT_LOG}"

echo ""
echo "[*] Output saved to: ${OUT_LOG}"
NBUGS=$(grep -c "runtime error" "${OUT_LOG}" 2>/dev/null || echo 0)
echo "[*] UBSan runtime errors found: ${NBUGS}"
echo "[*] Expected: 8 errors at heif_metadata.cc:204 and context.cc:1728,1762,1767,1774,1783"
