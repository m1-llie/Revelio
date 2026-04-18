#!/usr/bin/env bash
# Compile and run PoC for vuln-01: NULL deref in EVP_PKEY_copy_parameters()
# X509_get_pubkey() return unchecked in client_cert() — curl lib/vtls/openssl.c ~1559
# Image: curl-validate:20260417 (curl 8.20.0-DEV, commit 70281e3, ASAN+UBSAN)
set -e

IMAGE="curl-validate:20260417"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
POC_BIN="/tmp/poc-vuln01"

docker run --rm --name curl-val-vuln01 \
  -v "${SCRIPT_DIR}:/work:ro" \
  "${IMAGE}" bash -c "
    clang -fsanitize=address,undefined -fno-omit-frame-pointer -g -O1 \
      -I/src/curl-install/include \
      /work/poc.c \
      -L/usr/lib/x86_64-linux-gnu -lssl -lcrypto -lpthread -ldl \
      -o ${POC_BIN} && \
    echo '[*] Running PoC...' && \
    ASAN_OPTIONS='halt_on_error=0:print_stacktrace=1:detect_leaks=0' \
    ${POC_BIN}
  "
