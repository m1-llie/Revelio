#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

TARGETS=(
  "n132/arvo:14935-vul"
  "n132/arvo:10400-vul"
  "n132/arvo:1065-vul"
  "n132/arvo:368-vul"
  "n132/arvo:6521-vul"
  "n132/arvo:24993-vul"
  "n132/arvo:47101-vul"
  "n132/arvo:7189-vul"
  "n132/arvo:12818-vul"
  "n132/arvo:14467-vul"
)

COOLDOWN=600  # 10 minutes between runs

image_exists() { docker image inspect "$1" &>/dev/null; }

ensure_image() {
  local img="$1"
  if ! image_exists "$img"; then
    echo "[prepare] Pulling $img ..."
    docker pull "$img"
  fi
}

ensure_clean() {
  local vul_img="$1"
  local clean_img="${vul_img/-vul/-vul-clean}"
  if image_exists "$clean_img"; then
    echo "[prepare] $clean_img already exists, skipping."
    return
  fi
  echo "[prepare] Creating $clean_img from $vul_img ..."
  python -m vulagent.run.clean_arvo --image "$vul_img"
}

total=${#TARGETS[@]}
echo "============================================"
echo " ARVO Batch Run: $total targets"
echo " Cooldown between runs: ${COOLDOWN}s"
echo "============================================"
echo ""

# Phase 1: prepare all images
echo "=== Phase 1: Preparing Docker images ==="
for target in "${TARGETS[@]}"; do
  fix_img="${target/-vul/-fix}"
  ensure_image "$target"
  ensure_image "$fix_img"
  ensure_clean "$target"
done
echo ""
echo "=== All images ready ==="
echo ""

# Phase 2: run experiments
echo "=== Phase 2: Running experiments ==="
for i in "${!TARGETS[@]}"; do
  idx=$((i + 1))
  target="${TARGETS[$i]}"
  clean_img="${target/-vul/-vul-clean}"

  echo ""
  echo "============================================"
  echo " [$idx/$total] Running: $clean_img"
  echo " Started at: $(date '+%Y-%m-%d %H:%M:%S')"
  echo "============================================"

  python -m vulagent.run.detect --arvo "$clean_img" || {
    echo "[WARN] Run failed for $clean_img (exit $?), continuing..."
  }

  echo " Finished at: $(date '+%Y-%m-%d %H:%M:%S')"

  if (( idx < total )); then
    echo " Cooling down for $((COOLDOWN / 60)) minutes..."
    sleep "$COOLDOWN"
  fi
done

echo ""
echo "============================================"
echo " All $total experiments complete."
echo " Finished at: $(date '+%Y-%m-%d %H:%M:%S')"
echo "============================================"
