#!/usr/bin/env bash
# Build and run ALL 11 PROJ vulnerability PoCs against the latest PROJ build.
# Run inside or via: docker run --rm \
#   -v /scr2/yiwei/revelio/zero-day/1_reported/4-proj-260417:/bugs \
#   -v /tmp/PROJ-latest:/src/PROJ-latest:ro \
#   -v /tmp/proj4-latest-build:/proj4-latest-build:ro \
#   revelio/proj4-asan:latest bash /bugs/build_all.sh
set -e

BUGS="${BUGS:-/bugs}"
PROJ="${PROJ:-/src/PROJ-latest}"
LIB="${LIB:-/proj4-latest-build/lib/libproj.a}"
SQLITE="${SQLITE:-/usr/lib/x86_64-linux-gnu/libsqlite3.so.0}"
DATA="${PROJ_DATA:-/out/asan}"
ASAN="detect_leaks=0:halt_on_error=0"

cc()  { clang   -std=c11   -fsanitize=address -g -O1 -I$PROJ/src -I$PROJ/include "$@" $LIB -lpthread $SQLITE -ldl -lm -lstdc++; }
cxx() { clang++ -std=c++17 -fsanitize=address -g -O1 -I$PROJ/src -I$PROJ/include "$@" $LIB -lpthread $SQLITE -ldl -lm; }
cxi() { clang++ -std=c++17 -DFROM_PROJ_CPP -fsanitize=address -g -O1 -I$PROJ/src -I$PROJ/include "$@" $LIB -lpthread $SQLITE -ldl -lm; }
run() { local n=$1; shift; echo "--- $n ---"; ASAN_OPTIONS="$ASAN" PROJ_DATA=$DATA timeout 30 "$@" 2>&1 | tail -15; echo; }

echo "=== Building all PoCs ==="
cxi $BUGS/01-io-SF09-wktnode-stack-overflow/io_SF09_poc.cpp              -o /tmp/poc_01
cxx $BUGS/02-crs-SF01-projjson-stack-overflow/crs_SF01_poc_capi.cpp      -o /tmp/poc_02
cc  $BUGS/03-net-SF23-nfm-null-deref/net_SF23_poc.c                      -o /tmp/poc_03
cc  $BUGS/04-net-SF24-download-null-deref/net_SF24_poc.c                 -o /tmp/poc_04
cc  $BUGS/05-isea-SF08-silent-inverse-failure/isea_SF08_poc.c            -o /tmp/poc_05
cc  $BUGS/06-capi-SF22-null-deref-api-functions/capi_SF22_poc.c          -o /tmp/poc_06
cc  $BUGS/07-capi-SF04-dangling-string-ptr/capi_SF04_poc.c               -o /tmp/poc_07
cxx $BUGS/08-conv-SF02-null-deref-stack-oob/conv_SF02_poc.cpp            -o /tmp/poc_08
cxx $BUGS/09-grids-SF01-proj-grid-info-null/grids_SF01_poc.cpp           -o /tmp/poc_09
cxx $BUGS/10-grids-SF10-ntv2-destructor-overflow/grids_SF10_poc.cpp      -o /tmp/poc_10
cxi $BUGS/11-singleop-SF01-concatop-stack-overflow/singleop_SF01_poc.cpp -o /tmp/poc_11
echo "All compiled OK."
echo

echo "=== Running PoCs ==="
# Generate CRS input (500-depth is fast; increase to 5000 for deeper crash with 512KB stack)
python3 $BUGS/02-crs-SF01-projjson-stack-overflow/crs_SF01_gen.py 500 > /tmp/sf01_500.json

run "01-io-SF09  WKTNode stack overflow"      /tmp/poc_01
(ulimit -s 512; run "02-crs-SF01 DerivedCRS JSON stack overflow (512KB stack)" /tmp/poc_02 /tmp/sf01_500.json)
run "03-net-SF23 nfm_is_tilde_slash NULL deref"   /tmp/poc_03
run "04-net-SF24 proj_download_file NULL deref"   /tmp/poc_04
run "05-isea-SF08 ISEA silent inverse failure"    /tmp/poc_05
run "06-capi-SF22 NULL deref in 4 API functions"  /tmp/poc_06
run "07-capi-SF04 dangling string ptr"            /tmp/poc_07
run "08-conv-SF02 NULL params in proj_create_conversion" /tmp/poc_08
run "09-grids-SF01 proj_grid_info(NULL)"          /tmp/poc_09
run "10-grids-SF10 NTv2 destructor overflow" /tmp/poc_10 \
    $BUGS/10-grids-SF10-ntv2-destructor-overflow/sf10_deep.gsb
run "11-singleop-SF01 ConcatenatedOperation export overflow" /tmp/poc_11
