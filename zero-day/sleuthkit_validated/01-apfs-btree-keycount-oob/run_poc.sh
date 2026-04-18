#!/usr/bin/env bash
# Reproduce: APFS btree key_count OOB - use-of-uninitialized-value via attacker-controlled key_count
# Confirmed on: sleuthkit commit 01de034 (2026-04-15)
# Note: Requires MSan build; ASAN exits cleanly without detecting this bug
set -e

POC_IMG="/scr2/yiwei/vul-agent/zero-day/sleuthkit/01-apfs-btree-key-count-oob-read/apfs_btree_huge_key_count.img"
DOCKER_IMG="vulagent/sleuthkit:20260417"

echo "[*] Running PoC: APFS btree key_count OOB (MSan required)"
echo "[*] Image: $POC_IMG"
echo "[*] Note: Uses /out/msan/fls_apfs_fuzzer — ASAN binary exits cleanly"
echo ""
docker run --rm --memory=2g \
  -v "$(dirname "$POC_IMG"):/h" \
  "$DOCKER_IMG" \
  bash -c "MSAN_OPTIONS='halt_on_error=1:print_stacktrace=1' \
  /out/msan/fls_apfs_fuzzer /h/$(basename "$POC_IMG")" 2>&1 || true
