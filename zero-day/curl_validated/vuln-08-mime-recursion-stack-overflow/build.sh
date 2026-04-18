#!/usr/bin/env bash
# Compile and run PoC for vuln-08: Stack overflow via nested curl_mime_subparts()
# No recursion depth limit in readback_part -> mime_subparts_read chain
# curl lib/mime.c:684 — crashes with ~20000 levels under ASAN (~9500 in production)
# Image: curl-validate:20260417 (curl 8.20.0-DEV, commit 70281e3, ASAN+UBSAN)
set -e

IMAGE="curl-validate:20260417"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
POC_BIN="/tmp/poc-vuln08"
DEPTH="${1:-20000}"   # Use 20000 for ASAN; ~9500 for production release build

docker run --rm --name curl-val-vuln08 \
  -v "${SCRIPT_DIR}:/work:ro" \
  "${IMAGE}" bash -c "
    clang -fsanitize=address,undefined -fno-omit-frame-pointer -g -O1 \
      -I/src/curl-install/include \
      /work/poc.c \
      /src/curl/lib/.libs/libcurl.a \
      -L/usr/lib/x86_64-linux-gnu -lssl -lcrypto -lz -lpthread -ldl \
      -o ${POC_BIN} && \
    echo '[*] Running PoC with depth ${DEPTH}...' && \
    ASAN_OPTIONS='halt_on_error=0:print_stacktrace=1:detect_leaks=0' \
    ${POC_BIN} ${DEPTH}
  "
