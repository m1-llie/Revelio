#!/usr/bin/env bash
# Reproduce: FFS cg_iusedoff signed comparison bypass OOB read
# Confirmed on: sleuthkit commit 01de034 (2026-04-15)
set -e

POC_IMG="/scr2/yiwei/vul-agent/zero-day/sleuthkit/10-ffs-SF03-cgiusedoff-signed-comparison-bypass/ffs_cgiusedoff_oob_read.img"
DOCKER_IMG="vulagent/sleuthkit:20260417"

echo "[*] Running PoC: FFS SF03 cg_iusedoff signed comparison bypass OOB"
echo "[*] Image: $POC_IMG"
echo ""
docker run --rm --memory=2g \
  -v "$(dirname "$POC_IMG"):/h" \
  "$DOCKER_IMG" \
  bash -c "ASAN_OPTIONS='halt_on_error=1:print_stacktrace=1:detect_leaks=0' \
  /out/asan/fls_ffs_fuzzer /h/$(basename "$POC_IMG")" 2>&1 || true
