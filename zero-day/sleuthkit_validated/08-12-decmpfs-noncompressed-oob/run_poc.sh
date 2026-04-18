#!/usr/bin/env bash
# Reproduce: decmpfs noncompressed attr OOB read - heap-buffer-overflow 65536 bytes
# Issues 08 and 12 are the same bug; both PoC images are provided.
# Confirmed on: sleuthkit commit 01de034 (2026-04-15)
set -e

POC_IMG_08="/scr2/yiwei/vul-agent/zero-day/sleuthkit/08-decmpfs-SF07-noncompressed-oob-read/decmpfs_sf07_noncompressed_oob.img"
POC_IMG_12="/scr2/yiwei/vul-agent/zero-day/sleuthkit/12-hfs-decmpfs-noncompressed-oob-read/hfs_decmpfs_oob_read.img"
DOCKER_IMG="vulagent/sleuthkit:20260417"

echo "[*] Running PoC (issue 08): decmpfs SF07 noncompressed OOB read"
echo "[*] Image: $POC_IMG_08"
echo ""
docker run --rm --memory=2g \
  -v "$(dirname "$POC_IMG_08"):/h" \
  "$DOCKER_IMG" \
  bash -c "ASAN_OPTIONS='halt_on_error=1:print_stacktrace=1:detect_leaks=0' \
  /out/asan/fls_hfs_fuzzer /h/$(basename "$POC_IMG_08")" 2>&1 || true

echo ""
echo "[*] Running PoC (issue 12): HFS decmpfs OOB read (same bug, alternate image)"
echo "[*] Image: $POC_IMG_12"
echo ""
docker run --rm --memory=2g \
  -v "$(dirname "$POC_IMG_12"):/h" \
  "$DOCKER_IMG" \
  bash -c "ASAN_OPTIONS='halt_on_error=1:print_stacktrace=1:detect_leaks=0' \
  /out/asan/fls_hfs_fuzzer /h/$(basename "$POC_IMG_12")" 2>&1 || true
