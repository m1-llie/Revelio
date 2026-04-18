#!/usr/bin/env bash
# Reproduce: btrfs large number_of_items OOB read - heap-buffer-overflow
# Confirmed on: sleuthkit commit 01de034 (2026-04-15)
set -e

POC_IMG="/scr2/yiwei/vul-agent/zero-day/sleuthkit/05-btrfs-SF07-large-num-items-oob/btrfs_sf07_large_num_items.img"
DOCKER_IMG="vulagent/sleuthkit:20260417"

echo "[*] Running PoC: btrfs SF07 large number_of_items OOB"
echo "[*] Image: $POC_IMG"
echo ""
docker run --rm --memory=2g \
  -v "$(dirname "$POC_IMG"):/h" \
  "$DOCKER_IMG" \
  bash -c "ASAN_OPTIONS='halt_on_error=1:print_stacktrace=1:detect_leaks=0' \
  /out/asan/fls_btrfs_fuzzer /h/$(basename "$POC_IMG")" 2>&1 || true
