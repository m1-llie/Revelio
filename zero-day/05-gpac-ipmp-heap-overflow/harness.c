/* Fuzzing harness for GPAC IPMP Tool descriptor heap overflow.
   Calls gf_isom_open_file which parses moov->iods->IPMP descriptors.

   This bug is NOT reachable in OSS-Fuzz builds (GPAC_MINIMAL_ODF is defined),
   but affects any full/non-minimal GPAC build. */
#include <stdio.h>
#include <unistd.h>
#include <gpac/internal/isomedia_dev.h>
#include <gpac/constants.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    char filename[256];
    sprintf(filename, "/tmp/libfuzzer_ipmp.%d", getpid());
    FILE *fp = fopen(filename, "wb");
    if (!fp) return 0;
    fwrite(data, size, 1, fp);
    fclose(fp);
    GF_ISOFile *movie = gf_isom_open_file(filename, GF_ISOM_OPEN_READ_DUMP, NULL);
    if (movie) gf_isom_close(movie);
    unlink(filename);
    return 0;
}
