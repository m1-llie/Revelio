#!/usr/bin/env bash
# Reproduce: FFS itoo_lcl OOB read via anomalous fs_inopb - heap-buffer-overflow 128 bytes
# Confirmed on: sleuthkit commit 01de034 (2026-04-15)
set -e

POC_IMG="/scr2/yiwei/vul-agent/zero-day/sleuthkit/11-ffs-SF18-itoo-oob-read/ffs_itoo_oob_write.img"
DOCKER_IMG="vulagent/sleuthkit:20260417"

echo "[*] Running PoC: FFS SF18 itoo_lcl OOB read"
echo "[*] Image: $POC_IMG"
echo ""
docker run --rm --memory=2g \
  -v "$(dirname "$POC_IMG"):/h" \
  "$DOCKER_IMG" \
  bash -c "ASAN_OPTIONS='halt_on_error=1:print_stacktrace=1:detect_leaks=0' \
  /out/asan/fls_ffs_fuzzer /h/$(basename "$POC_IMG")" 2>&1 || true
