#!/bin/bash
# Reproduce: Assimp FBX ReadScope stack overflow
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
IMAGE="${1:-vulagent/assimp:latest}"
FUZZER="assimp_fuzzer_fbx"
POC="$SCRIPT_DIR/poc.fbx"

echo "[*] PoC: $POC ($(wc -c < "$POC") bytes)"
echo "[*] Running against $IMAGE / $FUZZER ..."
docker run --rm -v "$POC:/tmp/poc:ro" "$IMAGE" timeout 30 arvo run "$FUZZER" 2>&1 | \
    grep -E "AddressSanitizer|ERROR|SUMMARY|SCARINESS|stack-overflow" || true
echo "[*] Done."
