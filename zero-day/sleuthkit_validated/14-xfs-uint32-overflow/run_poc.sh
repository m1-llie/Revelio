#!/usr/bin/env bash
# Reproduce: XFS xfs_inode_get_offset uint32_t multiplication overflow
# Confirmed on: sleuthkit commit 01de034 (2026-04-15)
# Note: Requires UBSan build with -fsanitize=unsigned-integer-overflow
#       Standard ASAN/UBSan does NOT flag this (unsigned overflow is defined in C/C++)
set -e

POC_IMG="/scr2/yiwei/vul-agent/zero-day/sleuthkit/14-xfs-inode-get-offset-uint32-overflow/xfs_agno_overflow.img"
DOCKER_IMG="vulagent/sleuthkit:20260417"

echo "[*] Running PoC: XFS xfs_inode_get_offset uint32 overflow (UBSan)"
echo "[*] Image: $POC_IMG"
echo "[*] Note: /out/ubsan/fls_xfs_fuzzer must be built with -fsanitize=unsigned-integer-overflow"
echo ""
docker run --rm --memory=2g \
  -v "$(dirname "$POC_IMG"):/h" \
  "$DOCKER_IMG" \
  bash -c "UBSAN_OPTIONS='halt_on_error=0:print_stacktrace=1' \
  /out/ubsan/fls_xfs_fuzzer /h/$(basename "$POC_IMG")" 2>&1 || true
