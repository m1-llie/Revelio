#!/usr/bin/env bash
# Reproduce: ntfs_fix_idxrec upd_seq OOB read - heap-buffer-overflow 1 byte
# Confirmed on: sleuthkit commit 01de034 (2026-04-15)
set -e

POC_IMG="/scr2/yiwei/vul-agent/zero-day/sleuthkit/13-ntfs-idxrec-heap-buffer-overflow/ntfs_idxrec_oob.img"
DOCKER_IMG="vulagent/sleuthkit:20260417"

echo "[*] Running PoC: NTFS ntfs_fix_idxrec upd_seq OOB"
echo "[*] Image: $POC_IMG"
echo ""
docker run --rm --memory=2g \
  -v "$(dirname "$POC_IMG"):/h" \
  "$DOCKER_IMG" \
  bash -c "ASAN_OPTIONS='halt_on_error=1:print_stacktrace=1:detect_leaks=0' \
  /out/asan/fls_ntfs_fuzzer /h/$(basename "$POC_IMG")" 2>&1 || true
