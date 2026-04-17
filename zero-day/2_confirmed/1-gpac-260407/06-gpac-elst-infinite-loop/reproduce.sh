#!/bin/bash
# Reproduce: GPAC Edit List (elst) infinite processing loop
# The PoC causes 100% CPU with no termination. We use a 10-second timeout
# and count output packets to demonstrate the DoS.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
IMAGE="${1:-vulagent/gpac:latest}"
FUZZER="fuzz_probe_analyze"
POC="$SCRIPT_DIR/poc.mp4"

echo "[*] PoC: $POC ($(wc -c < "$POC") bytes)"
echo "[*] Running against $IMAGE / $FUZZER with 10s timeout..."
output=$(docker run --rm -v "$POC:/tmp/poc:ro" "$IMAGE" timeout 10 arvo run "$FUZZER" 2>&1 || true)
packet_count=$(echo "$output" | wc -l)
echo "[*] Output lines in 10 seconds: $packet_count"
if [ "$packet_count" -gt 10000 ]; then
    echo "[*] CONFIRMED: Infinite loop DoS — $packet_count packets emitted before timeout"
else
    echo "[*] Output was limited ($packet_count lines). Check manually."
    echo "$output" | tail -5
fi
echo "[*] Done."
