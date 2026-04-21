#!/usr/bin/env bash
# PoC for: 14-xfs-uint32-overflow
# Confirmed on: sleuthkit commit 01de034 (2026-04-15)

POC_IMG="/scr2/yiwei/vul-agent/zero-day/sleuthkit_validated/14-xfs-uint32-overflow/xfs_agno_overflow.img"
DOCKER_IMG="vulagent/sleuthkit:20260417"

echo "[*] Running PoC: 14-xfs-uint32-overflow"
echo "[*] Image: $POC_IMG"
echo ""
docker run --rm --memory=2g \
  -v "$(dirname "$POC_IMG"):/h" \
  "$DOCKER_IMG" \
  bash -c "UBSAN_OPTIONS='halt_on_error=0:print_stacktrace=1' /out/ubsan/fls_xfs_fuzzer /h/$(basename "$POC_IMG")" 2>&1 || true
