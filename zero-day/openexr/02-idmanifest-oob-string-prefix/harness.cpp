// Custom harness to trigger IDManifest parsing via decompression
// Reads a raw IDManifest binary (uncompressed) and calls init() via
// the IDManifest(const char*, const char*) constructor
// Usage: ./idmanifest_harness <raw_manifest_binary>

#include <ImfIDManifest.h>
#include <Iex.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <vector>
#include <stdexcept>

using OPENEXR_IMF_NAMESPACE::IDManifest;

int main(int argc, char** argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <raw_manifest.bin>\n", argv[0]);
        return 1;
    }

    FILE* f = fopen(argv[1], "rb");
    if (!f) {
        fprintf(stderr, "Cannot open %s\n", argv[1]);
        return 1;
    }

    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);

    std::vector<char> data(size);
    if (fread(data.data(), 1, size, f) != (size_t)size) {
        fprintf(stderr, "Read error\n");
        fclose(f);
        return 1;
    }
    fclose(f);

    fprintf(stderr, "Parsing IDManifest binary: %s (%ld bytes)\n", argv[1], size);

    try {
        IDManifest manifest(data.data(), data.data() + size);
        fprintf(stderr, "Parsed OK: %zu channel groups\n", manifest.size());
    } catch (const IEX_NAMESPACE::BaseExc& e) {
        fprintf(stderr, "IEX Exception: %s\n", e.what());
        return 2;
    } catch (const std::exception& e) {
        fprintf(stderr, "Exception: %s\n", e.what());
        return 3;
    } catch (...) {
        fprintf(stderr, "Unknown exception\n");
        return 4;
    }

    return 0;
}
