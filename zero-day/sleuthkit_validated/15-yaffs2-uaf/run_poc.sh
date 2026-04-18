#!/usr/bin/env bash
# Reproduce: YAFFS2 use-after-free - yaffs2_open() returns dangling pointer
# Confirmed on: sleuthkit commit 01de034 (2026-04-15)
# Note: The standalone fuzzer may not trigger ASAN; a dedicated driver calling
#       tsk_fs_fls(fs, ...) after open reliably triggers heap-use-after-free.
set -e

POC_IMG="/scr2/yiwei/vul-agent/zero-day/sleuthkit/15-yaffs-uaf-yaffs2-open-unique-ptr/yaffs_uaf_minimal.img"
DOCKER_IMG="vulagent/sleuthkit:20260417"

echo "[*] Running PoC: YAFFS2 UAF via yaffs2_open() dangling pointer"
echo "[*] Image: $POC_IMG"
echo "[*] Note: ASAN standalone harness may exit cleanly; UAF confirmed by code inspection"
echo "[*]       and dedicated driver (tsk_fs_fls after tsk_fs_open_img triggers ASAN)"
echo ""
docker run --rm --memory=2g \
  -v "$(dirname "$POC_IMG"):/h" \
  "$DOCKER_IMG" \
  bash -c "ASAN_OPTIONS='halt_on_error=1:print_stacktrace=1:detect_leaks=0' \
  /out/asan/fls_yaffs_fuzzer /h/$(basename "$POC_IMG")" 2>&1 || true
