#!/usr/bin/env bash
# build.sh — compile and run both POCs inside the revelio/libheif docker image
#
# Prerequisites:
#   - Docker with image revelio/libheif:latest
#   - python3 (to generate test HEIF files)
#
# Usage: bash build.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IMAGE="revelio/libheif:latest"
ASAN_OPTIONS="detect_leaks=0:abort_on_error=1:print_stacktrace=1"
OUTPUT_TXT="${SCRIPT_DIR}/asan_output_validated.txt"

# ---- Step 0: generate the minimal HEIF test files ---------------------------
echo "[build.sh] Generating test HEIF files..."
python3 "${SCRIPT_DIR}/gen_heif.py"

echo "[build.sh] Building libheif (static+ASAN) and compiling POCs inside Docker..."
echo "[build.sh] Output will be tee'd to: ${OUTPUT_TXT}"

docker run --rm \
  -v "${SCRIPT_DIR}/poc_07_get_track_ids.cc:/tmp/poc07.cc:ro" \
  -v "${SCRIPT_DIR}/poc_08_get_reference_types.cc:/tmp/poc08.cc:ro" \
  -v "${SCRIPT_DIR}/poc07_10tracks.heif:/tmp/poc07_10tracks.heif:ro" \
  -v "${SCRIPT_DIR}/poc08_10reftypes.heif:/tmp/poc08_10reftypes.heif:ro" \
  -e ASAN_OPTIONS="${ASAN_OPTIONS}" \
  "${IMAGE}" bash -c '
set -euo pipefail

# ---- 1. Build libheif as a static ASAN library ----------------------------
echo "=== [1/4] Configuring libheif with ASAN (static) ==="
mkdir -p /tmp/heifbuild && cd /tmp/heifbuild

export CC=clang
export CXX=clang++

cmake /src/libheif \
  -DCMAKE_C_FLAGS="-fsanitize=address,undefined -g -fno-omit-frame-pointer" \
  -DCMAKE_CXX_FLAGS="-fsanitize=address,undefined -g -fno-omit-frame-pointer" \
  -DCMAKE_EXE_LINKER_FLAGS="-fsanitize=address,undefined" \
  -DCMAKE_SHARED_LINKER_FLAGS="-fsanitize=address,undefined" \
  -DBUILD_SHARED_LIBS=OFF \
  -DWITH_EXAMPLES=OFF \
  -DWITH_UNCOMPRESSED_CODEC=OFF \
  -DWITH_DAV1D=OFF \
  -DWITH_VVDEC=OFF \
  -DWITH_VVENC=OFF \
  -DWITH_AOM_ENCODER=OFF \
  -DWITH_X265=OFF \
  -DWITH_X264=OFF \
  -DWITH_OpenH264_DECODER=OFF \
  -DWITH_OpenH264_ENCODER=OFF \
  -DWITH_OpenJPEG_ENCODER=OFF \
  -DWITH_OpenJPEG_DECODER=OFF \
  -DWITH_OPENJPH_ENCODER=OFF \
  -DWITH_JPEG_DECODER=OFF \
  -DWITH_JPEG_ENCODER=OFF \
  -DWITH_LIBSHARPYUV=OFF \
  -DCMAKE_BUILD_TYPE=Debug \
  -G "Unix Makefiles" \
  2>&1 | tail -5

echo "=== [2/4] Building libheif (static) ==="
make -j"$(nproc)" heif 2>&1 | tail -5

HEIF_LIB=/tmp/heifbuild/libheif/libheif.a
HEIF_INC=/src/libheif/libheif/api
# heif_version.h is generated at /tmp/heifbuild/libheif/heif_version.h
# heif_library.h uses: #include <libheif/heif_version.h>
# so we pass the parent dir (/tmp/heifbuild) so the path resolves correctly
HEIF_GEN=/tmp/heifbuild

CXXFLAGS="-fsanitize=address,undefined -g -fno-omit-frame-pointer -std=c++17"
LDFLAGS="-L/usr/lib/x86_64-linux-gnu -l:libz.so.1 -lm -lpthread -ldl"

# ---- 2. Compile POC 07 -----------------------------------------------------
echo ""
echo "=== [3/4] Compiling poc07 (heif_context_get_track_ids OOB) ==="
clang++ ${CXXFLAGS} \
  -I"${HEIF_INC}" -I"${HEIF_GEN}" \
  -o /tmp/poc07 /tmp/poc07.cc \
  "${HEIF_LIB}" ${LDFLAGS} \
  2>&1
echo "=== [3/4] poc07 compiled OK ==="

# ---- 3. Compile POC 08 -----------------------------------------------------
echo "=== [4/4] Compiling poc08 (heif_track_get_track_reference_types OOB) ==="
clang++ ${CXXFLAGS} \
  -I"${HEIF_INC}" -I"${HEIF_GEN}" \
  -o /tmp/poc08 /tmp/poc08.cc \
  "${HEIF_LIB}" ${LDFLAGS} \
  2>&1
echo "=== [4/4] poc08 compiled OK ==="

# ---- 4. Run both POCs -------------------------------------------------------
echo ""
echo "=================================================================="
echo "  RUNNING POC 07 — heif_context_get_track_ids() OOB write"
echo "  Input: /tmp/poc07_10tracks.heif (10 metadata tracks)"
echo "  Buffer: 2 slots — overflow by 8 uint32_t words"
echo "=================================================================="
/tmp/poc07 /tmp/poc07_10tracks.heif 2>&1 || true

echo ""
echo "=================================================================="
echo "  RUNNING POC 08 — heif_track_get_track_reference_types() OOB write"
echo "  Input: /tmp/poc08_10reftypes.heif (1 track with 10 tref types)"
echo "  Buffer: 1 slot — overflow by 9 uint32_t words"
echo "=================================================================="
/tmp/poc08 /tmp/poc08_10reftypes.heif 2>&1 || true
' 2>&1 | tee "${OUTPUT_TXT}"

echo ""
echo "[build.sh] Done. ASAN output saved to: ${OUTPUT_TXT}"
