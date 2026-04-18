#!/usr/bin/env bash
# Reproduce libheif OOB in SampleAuxInfoReader constructor
# (saiz sample count exceeds stco/stsc chunk coverage)
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

echo "[*] Pulling vulagent/libheif:latest"
docker pull vulagent/libheif:latest 2>/dev/null || true

echo "[*] Running ASAN file_fuzzer against poc_input"
docker run --rm \
    -v "${SCRIPT_DIR}:/poc" \
    -e ASAN_OPTIONS="detect_leaks=0:print_stacktrace=1:symbolize=1" \
    vulagent/libheif:latest \
    /out/asan/file_fuzzer /poc/poc_input 2>&1

echo ""
echo "[*] Expected: SIGABRT at SampleAuxInfoReader::SampleAuxInfoReader"
echo "    (track.cc:141 — assert current_chunk < chunks.size())"
