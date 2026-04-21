#!/usr/bin/env bash
# PoC for: 06-btrfs-sf09-dir-entry-oob
# Confirmed on: sleuthkit commit 01de034 (2026-04-15)

POC_IMG="/scr2/yiwei/vul-agent/zero-day/sleuthkit_validated/06-btrfs-sf09-dir-entry-oob/btrfs_sf09_dir_entry_oob_v2.img"
DOCKER_IMG="vulagent/sleuthkit:20260417"

echo "[*] Running PoC: 06-btrfs-sf09-dir-entry-oob"
echo "[*] Image: $POC_IMG"
echo ""
docker run --rm --memory=2g \
  -v "$(dirname "$POC_IMG"):/h" \
  "$DOCKER_IMG" \
  bash -c "ASAN_OPTIONS='halt_on_error=1:print_stacktrace=1:detect_leaks=0' /out/asan/fls_btrfs_fuzzer /h/$(basename "$POC_IMG")" 2>&1 || true
