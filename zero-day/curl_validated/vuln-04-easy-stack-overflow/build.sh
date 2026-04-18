#!/usr/bin/env bash
# Compile and run PoC for vuln-04: Stack overflow in populate_fds()
# fds[4] overflows with 5+ sockets via curl_easy_perform_ev() — curl lib/easy.c
# Image: curl-validate:20260417 (curl 8.20.0-DEV, commit 70281e3, ASAN+UBSAN)
set -e

IMAGE="curl-validate:20260417"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
POC_BIN="/tmp/poc-vuln04"

docker run --rm --name curl-val-vuln04 \
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
    ${POC_BIN}
  "
