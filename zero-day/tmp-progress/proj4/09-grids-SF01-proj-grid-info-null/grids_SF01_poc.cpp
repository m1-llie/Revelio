/*
 * PoC for SF01: NULL pointer dereference / logic_error in proj_grid_info()
 * when gridname parameter is NULL.
 *
 * Bug: proj_grid_info(NULL) passes NULL to std::string constructor inside
 * the lambda `fillGridInfo`, causing std::logic_error:
 *   "basic_string::_M_construct null not valid"
 *
 * Affected file: PROJ/src/grids.cpp, proj_grid_info() function
 * The lambda captures `gridname` and calls strncpy(grinfo.gridname, gridname, ...)
 * and pj_find_file(ctx, gridname, ...). Before that, even open() functions
 * receive NULL which leads to std::string constructor with NULL.
 *
 * Compile:
 *   clang++ -std=c++17 -fsanitize=address -g -O1 \
 *     -I/src/PROJ/include -I/src/PROJ/src \
 *     grids_SF01_poc.cpp \
 *     /proj4-build/lib/libproj.a \
 *     -lpthread /host-lib/libsqlite3.so.0 -ldl -lm \
 *     -o poc_sf01
 *   ASAN_OPTIONS=detect_leaks=0 PROJ_DATA=/out/asan ./poc_sf01
 */

#include <stdio.h>
#include <stdlib.h>
#include <proj.h>

int main(void) {
    printf("Testing SF01: proj_grid_info(NULL) - NULL parameter crash\n");
    fflush(stdout);

    /* Calling proj_grid_info with NULL triggers std::logic_error
     * "basic_string::_M_construct null not valid"
     * causing program abort (terminate called) */
    PJ_GRID_INFO info = proj_grid_info(NULL);

    /* Should not reach here */
    printf("BUG: Should have crashed! format=%s\n", info.format);
    return 1;
}
