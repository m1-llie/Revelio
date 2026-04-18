#!/usr/bin/env bash
# Reproduce: decmpfs uncSize integer overflow -> allocation-size-too-big
# Confirmed on: sleuthkit commit 01de034 (2026-04-15)
set -e

POC_IMG="/scr2/yiwei/vul-agent/zero-day/sleuthkit/07-decmpfs-SF02-uncsize-integer-overflow/decmpfs_sf02_uncsize_overflow.img"
DOCKER_IMG="vulagent/sleuthkit:20260417"

echo "[*] Running PoC: decmpfs SF02 uncSize integer overflow"
echo "[*] Image: $POC_IMG"
echo ""
docker run --rm --memory=2g \
  -v "$(dirname "$POC_IMG"):/h" \
  "$DOCKER_IMG" \
  bash -c "ASAN_OPTIONS='halt_on_error=1:print_stacktrace=1:detect_leaks=0' \
  /out/asan/fls_hfs_fuzzer /h/$(basename "$POC_IMG")" 2>&1 || true
