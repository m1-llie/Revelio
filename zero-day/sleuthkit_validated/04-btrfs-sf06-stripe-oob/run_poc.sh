#!/usr/bin/env bash
# Reproduce: btrfs chunk item stripe_count OOB read - heap-buffer-overflow
# Confirmed on: sleuthkit commit 01de034 (2026-04-15)
set -e

POC_IMG="/scr2/yiwei/vul-agent/zero-day/sleuthkit/04-btrfs-SF06-stripe-count-oob/btrfs_sf06_stripe_oob.img"
DOCKER_IMG="vulagent/sleuthkit:20260417"

echo "[*] Running PoC: btrfs SF06 stripe count OOB"
echo "[*] Image: $POC_IMG"
echo ""
docker run --rm --memory=2g \
  -v "$(dirname "$POC_IMG"):/h" \
  "$DOCKER_IMG" \
  bash -c "ASAN_OPTIONS='halt_on_error=1:print_stacktrace=1:detect_leaks=0' \
  /out/asan/fls_btrfs_fuzzer /h/$(basename "$POC_IMG")" 2>&1 || true
