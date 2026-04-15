#!/usr/bin/env bash
set -euo pipefail

# prepare_ossfuzz_project.sh — Build & package OSS-Fuzz projects for vulagent.
#
# Turns any OSS-Fuzz project into a vulagent-ready Docker image (same interface
# as ARVO images). Clones/updates oss-fuzz, builds fuzzers per sanitizer,
# packages into vulagent/<project>:latest, and cleans for zero-day detection.
#
# Usage:
#   scripts/prepare_ossfuzz_project.sh <project> [project2 ...]
#   scripts/prepare_ossfuzz_project.sh --sanitizers asan,ubsan openssl
#   scripts/prepare_ossfuzz_project.sh --oss-fuzz-dir /data/oss-fuzz openssl


SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

OSS_FUZZ_DIR="${OSS_FUZZ_DIR:-$HOME/oss-fuzz}"
SANITIZERS="asan,ubsan,msan"
PROJECTS=()

usage() {
    cat <<EOF
Usage: $(basename "$0") [OPTIONS] <project> [project2 ...]

Build and package OSS-Fuzz projects into vulagent-ready Docker images.

Options:
  --oss-fuzz-dir DIR    Path to oss-fuzz checkout (default: ~/oss-fuzz)
  --sanitizers LIST     Comma-separated sanitizers (default: asan,ubsan,msan)
  --help                Show this help

Examples:
  $(basename "$0") openssl
  $(basename "$0") --sanitizers asan,ubsan openssl assimp
  $(basename "$0") --oss-fuzz-dir /data/oss-fuzz openssl
EOF
    exit 0
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --oss-fuzz-dir) OSS_FUZZ_DIR="$2"; shift 2 ;;
        --sanitizers)   SANITIZERS="$2"; shift 2 ;;
        --help|-h)      usage ;;
        -*)             echo "Unknown option: $1" >&2; exit 1 ;;
        *)              PROJECTS+=("$1"); shift ;;
    esac
done

if [[ ${#PROJECTS[@]} -eq 0 ]]; then
    echo "ERROR: no projects specified" >&2
    usage
fi

# Map sanitizer short names to oss-fuzz --sanitizer values
declare -A SAN_MAP=(
    [asan]=address
    [ubsan]=undefined
    [msan]=memory
)

IFS=',' read -ra SAN_LIST <<< "$SANITIZERS"
for san in "${SAN_LIST[@]}"; do
    if [[ -z "${SAN_MAP[$san]+_}" ]]; then
        echo "ERROR: unknown sanitizer '${san}' (valid: asan, ubsan, msan)" >&2
        exit 1
    fi
done

# ── Step 0: Ensure oss-fuzz is available ─────────────────────────────────────

if [[ ! -d "$OSS_FUZZ_DIR" ]]; then
    echo "==> Cloning oss-fuzz into ${OSS_FUZZ_DIR}..."
    git clone --depth 1 https://github.com/google/oss-fuzz.git "$OSS_FUZZ_DIR"
else
    echo "==> Updating oss-fuzz at ${OSS_FUZZ_DIR}..."
    git -C "$OSS_FUZZ_DIR" pull --ff-only 2>/dev/null || true
fi

# ── Per-project pipeline ─────────────────────────────────────────────────────

for PROJECT in "${PROJECTS[@]}"; do
    echo ""
    echo "================================================================"
    echo "  Project: ${PROJECT}"
    echo "================================================================"

    PROJECT_DIR="${OSS_FUZZ_DIR}/projects/${PROJECT}"
    if [[ ! -d "$PROJECT_DIR" ]]; then
        echo "ERROR: project '${PROJECT}' not found in ${OSS_FUZZ_DIR}/projects/" >&2
        echo "Check available projects: ls ${OSS_FUZZ_DIR}/projects/" >&2
        continue
    fi

    # ── Step 1: Build fuzzers for each sanitizer ─────────────────────────
    built_sanitizers=()

    for san in "${SAN_LIST[@]}"; do
        oss_san="${SAN_MAP[$san]}"
        echo ""
        echo "--- Building ${PROJECT} with ${san} (--sanitizer ${oss_san}) ---"

        if python3 "${OSS_FUZZ_DIR}/infra/helper.py" build_fuzzers \
                --sanitizer "$oss_san" "$PROJECT"; then

            # Save build output before next sanitizer build overwrites it
            SAN_OUT="${OSS_FUZZ_DIR}/build/out/${PROJECT}_${san}"
            rm -rf "$SAN_OUT"
            cp -r "${OSS_FUZZ_DIR}/build/out/${PROJECT}" "$SAN_OUT"
            built_sanitizers+=("$san")
            echo "--- ${san}: OK (saved to ${SAN_OUT}) ---"
        else
            echo "--- ${san}: FAILED (skipping) ---"
        fi
    done

    if [[ ${#built_sanitizers[@]} -eq 0 ]]; then
        echo "ERROR: all sanitizer builds failed for ${PROJECT}, skipping" >&2
        continue
    fi

    # Clean up the generic build dir
    rm -rf "${OSS_FUZZ_DIR}/build/out/${PROJECT}"

    # ── Step 2: Package into a Docker image ──────────────────────────────

    CONTAINER="vulagent-setup-${PROJECT}"
    echo ""
    echo "--- Packaging ${PROJECT} (sanitizers: ${built_sanitizers[*]}) ---"

    docker rm -f "$CONTAINER" 2>/dev/null || true
    docker run -d --name "$CONTAINER" "gcr.io/oss-fuzz/${PROJECT}:latest" sleep 3600

    # Copy each sanitizer's fuzzer binaries into /out/<sanitizer>/
    for san in "${built_sanitizers[@]}"; do
        SAN_OUT="${OSS_FUZZ_DIR}/build/out/${PROJECT}_${san}"
        docker exec "$CONTAINER" mkdir -p "/out/${san}"
        docker cp "${SAN_OUT}/." "${CONTAINER}:/out/${san}/"
    done

    if [[ "$PROJECT" == "v8" ]]; then
        ARVO_SCRIPT="${SCRIPT_DIR}/arvo_v8"
    else
        ARVO_SCRIPT="${SCRIPT_DIR}/arvo_ossfuzz"
    fi

    if [[ ! -f "$ARVO_SCRIPT" ]]; then
        echo "ERROR: arvo script not found at ${ARVO_SCRIPT}" >&2
        docker rm -f "$CONTAINER"
        exit 1
    fi

    # Install the arvo runner script
    docker cp "$ARVO_SCRIPT" "${CONTAINER}:/usr/bin/arvo"
    docker exec "$CONTAINER" chmod +x /usr/bin/arvo

    # ── Step 3: Clean for zero-day detection (same as clean_arvo.py) ─────

    echo "--- Cleaning image (removing seeds, crashers, PoCs, .git) ---"
    docker exec "$CONTAINER" bash -c 'rm -f /tmp/poc' || true
    docker exec "$CONTAINER" bash -c 'find /out -maxdepth 2 -type f -name "*seed_corpus*.zip" -delete 2>/dev/null' || true
    docker exec "$CONTAINER" bash -c 'find /src -type f -name "*seed_corpus*" -delete 2>/dev/null' || true
    docker exec "$CONTAINER" bash -c 'find /src -type f -name "*corpus*.zip" -delete 2>/dev/null' || true
    docker exec "$CONTAINER" bash -c 'find /src -type d -name "seeds" -exec rm -rf {} + 2>/dev/null' || true
    docker exec "$CONTAINER" bash -c 'find /src -type d -name "corpus" -exec rm -rf {} + 2>/dev/null' || true
    docker exec "$CONTAINER" bash -c 'find /src -type d -regex ".*/corpus_[a-z0-9_]*" -exec rm -rf {} + 2>/dev/null' || true
    docker exec "$CONTAINER" bash -c 'find /src -name "crash-*" -delete 2>/dev/null' || true
    docker exec "$CONTAINER" bash -c 'rm -rf /src/afl/testcases /src/afl/docs/vuln_samples /src/aflplusplus/testcases /src/honggfuzz/examples /src/fuzzer-test-suite 2>/dev/null' || true
    docker exec "$CONTAINER" bash -c 'find /src -maxdepth 3 -type d -name ".git" | xargs rm -rf 2>/dev/null' || true

    # ── Step 4: Verify and commit ────────────────────────────────────────

    echo ""
    echo "Available fuzzers:"
    docker exec "$CONTAINER" arvo list --all

    IMAGE_TAG="vulagent/${PROJECT}:latest"
    docker commit "$CONTAINER" "$IMAGE_TAG"
    docker rm -f "$CONTAINER"

    # Clean up saved build artifacts
    for san in "${built_sanitizers[@]}"; do
        rm -rf "${OSS_FUZZ_DIR}/build/out/${PROJECT}_${san}"
    done

    echo ""
    echo "================================================================"
    echo "  Done: ${IMAGE_TAG}"
    echo "  Sanitizers: ${built_sanitizers[*]}"
    echo ""
    echo "  Usage:"
    echo "    python -m vulagent.run.detect --arvo ${IMAGE_TAG} --model <model>"
    echo "================================================================"
done
