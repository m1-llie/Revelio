#!/usr/bin/env bash
# Reproduce: btrfs dir entry data_len OOB - heap-buffer-overflow 28672 bytes
# Confirmed on: sleuthkit commit 01de034 (2026-04-15)
set -e

POC_IMG="/scr2/yiwei/vul-agent/zero-day/sleuthkit/06-btrfs-SF09-dir-entry-data-len-oob/btrfs_sf09_dir_entry_oob_v2.img"
DOCKER_IMG="vulagent/sleuthkit:20260417"

echo "[*] Running PoC: btrfs SF09 dir entry data_len OOB"
echo "[*] Image: $POC_IMG"
echo ""
docker run --rm --memory=2g \
  -v "$(dirname "$POC_IMG"):/h" \
  "$DOCKER_IMG" \
  bash -c "ASAN_OPTIONS='halt_on_error=1:print_stacktrace=1:detect_leaks=0' \
  /out/asan/fls_btrfs_fuzzer /h/$(basename "$POC_IMG")" 2>&1 || true
