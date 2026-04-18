#!/usr/bin/env bash
# Compile and run PoC for vuln-06: OOB read in Curl_ssl_session_import()
# shmac_len validates declared size but actual buffer can be smaller
# curl lib/vtls/vtls_scache.c — requires USE_SSLS_EXPORT (--enable-ssls-export)
# Image: curl-validate:20260417 (curl 8.20.0-DEV, commit 70281e3, ASAN+UBSAN)
set -e

IMAGE="curl-validate:20260417"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
POC_BIN="/tmp/poc-vuln06"

docker run --rm --name curl-val-vuln06 \
  -v "${SCRIPT_DIR}:/work:ro" \
  "${IMAGE}" bash -c "
    clang -fsanitize=address,undefined -fno-omit-frame-pointer -g -O1 \
      -I/src/curl-install/include \
      /work/poc.c \
      /src/curl/lib/.libs/libcurl.a \
      -L/usr/lib/x86_64-linux-gnu -lssl -lcrypto -lz -lpthread -ldl \
      -o ${POC_BIN} && \
    echo '[*] Running PoC...' && \
    ASAN_OPTIONS='halt_on_error=0:print_stacktrace=1:detect_leaks=0' \
    UBSAN_OPTIONS='print_stacktrace=1:halt_on_error=0' \
    ${POC_BIN}
  "
