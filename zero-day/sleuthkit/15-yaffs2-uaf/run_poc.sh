#!/usr/bin/env bash
# PoC for: 15-yaffs2-uaf
# Confirmed on: sleuthkit commit 01de034 (2026-04-15)

POC_IMG="/scr2/yiwei/vul-agent/zero-day/sleuthkit_validated/15-yaffs2-uaf/yaffs_uaf_minimal.img"
DOCKER_IMG="vulagent/sleuthkit:20260417"

echo "[*] Running PoC: 15-yaffs2-uaf"
echo "[*] Image: $POC_IMG"
echo ""
docker run --rm --memory=2g \
  -v "$(dirname "$POC_IMG"):/h" \
  "$DOCKER_IMG" \
  bash -c "ASAN_OPTIONS='halt_on_error=1:print_stacktrace=1:detect_leaks=0' /out/asan/fls_yaffs_fuzzer /h/$(basename "$POC_IMG")" 2>&1 || true
