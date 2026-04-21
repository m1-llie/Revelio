#!/usr/bin/env bash
# PoC for: 08-12-decmpfs-noncompressed-oob (same bug, two images)
# Confirmed on: sleuthkit commit 01de034 (2026-04-15)

BASE="/scr2/yiwei/vul-agent/zero-day/sleuthkit_validated/08-12-decmpfs-noncompressed-oob"
DOCKER_IMG="vulagent/sleuthkit:20260417"

for IMG in decmpfs_sf07_noncompressed_oob.img hfs_decmpfs_oob_read.img; do
  echo "[*] Running PoC: $IMG"
  docker run --rm --memory=2g \
    -v "$BASE:/h" \
    "$DOCKER_IMG" \
    bash -c "ASAN_OPTIONS='halt_on_error=1:print_stacktrace=1:detect_leaks=0' /out/asan/fls_hfs_fuzzer /h/$IMG" 2>&1 || true
  echo ""
done
