#!/usr/bin/env bash
# Build and run PoC: heap-buffer-overflow in dnsmasq log_query() via DS record
# Requires clang with AddressSanitizer support.
# Usage: bash build.sh
set -e

POC_SRC="$(dirname "$0")/poc_reproducer.c"
POC_BIN="/tmp/poc_dnsmasq_ds_overflow"

echo "[*] Compiling PoC with ASAN/UBSAN ..."
clang -fsanitize=address,undefined -fno-omit-frame-pointer -g -O1 \
    "$POC_SRC" -o "$POC_BIN"

echo "[*] Running PoC ..."
echo "    Expected: heap-buffer-overflow WRITE of size 58 into 46-byte buffer"
echo ""
ASAN_OPTIONS="halt_on_error=1:print_stacktrace=1:detect_leaks=0" "$POC_BIN" 2>&1 || true
