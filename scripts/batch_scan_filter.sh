#!/usr/bin/env bash
# =============================================================================
# batch_scan_filter.sh
#
# Run `python -m revelio.run.detect --pipeline scan_filter` across many
# (project, file) pairs. Projects run in parallel; files within a project run
# sequentially by default (same API key + same Docker image -> avoid rate limits
# and memory contention). The unit of work is a single (project, file) pair
# because --target-file accepts only one path today.
#
# ---- usage ------------------------------------------------------------------
#   scripts/batch_scan_filter.sh scripts/batch_scan_filter/jobs.tsv
#
# Long-running? Detach it:
#   nohup scripts/batch_scan_filter.sh scripts/batch_scan_filter/jobs.tsv \
#     > batch.out 2>&1 &
# or use tmux/screen.
#
# ---- inputs -----------------------------------------------------------------
# jobs.tsv is tab-separated with columns:
#   name  image  model  api_key_env  files_file  [extra_args]
#
#   name          short tag used in logs (e.g. openssl)
#   image         Docker image (e.g. revelio/openssl:latest)
#   model         --hypothesis-model value (e.g. anthropic/claude-haiku-4-5)
#   api_key_env   name of the env var that holds the API key (NOT the key
#                 itself). The script reads ${!api_key_env} at runtime.
#   files_file    path to a text file with one target file per line; '#'
#                 comments and blank lines are ignored. Relative paths are
#                 resolved against the jobs.tsv's directory.
#   extra_args    optional, passed verbatim to detect.py (put at end)
#
# ---- env knobs --------------------------------------------------------------
#   PROJECT_CONCURRENCY  max projects running at once         (default: 8)
#   FILES_CONCURRENCY    files per project running at once    (default: 1)
#   MAX_WORKERS          --max-workers passed to detect.py    (default: 4)
#   TOP_N                --top-n passed to detect.py          (default: 10)
#   BATCH_DIR            base output dir                      (default: batch/batch_<ts>)
#   RESUME               if "1", skip pairs already marked done  (default: 0)
#   DRY_RUN              if "1", print commands but don't run    (default: 0)
#   ENV_FILE             optional path to a file sourced for API keys
#   MAX_RETRIES          retries on transient errors             (default: 3)
#   RETRY_BACKOFF        space-separated sleep seconds per retry (default: "30 120 300")
#   HEARTBEAT_INTERVAL   seconds between progress lines; 0 off   (default: 60)
#
# ---- error handling ---------------------------------------------------------
# Each invocation is classified by log-tail pattern after a failure:
#   * quota      -> mark the key dead (all future jobs using this env var skip
#                   with KEY_DEAD). No retry.
#   * auth       -> same as quota.
#   * transient  -> retry up to MAX_RETRIES with RETRY_BACKOFF between attempts.
#   * other      -> don't retry; record as FAIL:rc_<n>.
# If EVERY distinct api_key_env in jobs.tsv is dead, the batch is aborted.
# Per-run state lives under $BATCH_DIR/state/keys/<env>.dead so sibling
# projects see the disable immediately. A heartbeat line is printed every
# HEARTBEAT_INTERVAL seconds with cumulative counts and dead keys.
#
# ---- outputs ----------------------------------------------------------------
#   $BATCH_DIR/
#     batch.log                  driver log (this script's own stdout/stderr)
#     logs/<name>__<file>.log    one log per (project, file) invocation
#     done/<name>__<file>        sentinel file for RESUME=1
#     state/keys/<env>.dead      marker for a key exhausted this run
#     summary.tsv                one row per pair: project, file, run_id,
#                                status, hypothesis_count, elapsed_s, log_path
#                                status is one of: OK | FAIL:quota | FAIL:auth
#                                | FAIL:transient | FAIL:rc_<n> | KEY_DEAD
#                                | MISSING_KEY
# =============================================================================

set -Eeuo pipefail

# -----------------------------------------------------------------------------
# args and defaults
# -----------------------------------------------------------------------------
if [[ $# -lt 1 ]]; then
    echo "usage: $0 <jobs.tsv>" >&2
    exit 2
fi

JOBS_TSV="$1"
[[ -f "$JOBS_TSV" ]] || { echo "FATAL: jobs file '$JOBS_TSV' not found" >&2; exit 2; }
JOBS_TSV="$(readlink -f "$JOBS_TSV")"
JOBS_DIR="$(dirname "$JOBS_TSV")"

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

BATCH_TS="$(date -u +%Y%m%d-%H%M%S)"
BATCH_DIR="${BATCH_DIR:-batch/batch_$BATCH_TS}"
LOGS_DIR="$BATCH_DIR/logs"
DONE_DIR="$BATCH_DIR/done"
SUMMARY_TSV="$BATCH_DIR/summary.tsv"
DRIVER_LOG="$BATCH_DIR/batch.log"

PROJECT_CONCURRENCY="${PROJECT_CONCURRENCY:-8}"
FILES_CONCURRENCY="${FILES_CONCURRENCY:-1}"
MAX_WORKERS="${MAX_WORKERS:-4}"
TOP_N="${TOP_N:-10}"
RESUME="${RESUME:-0}"
DRY_RUN="${DRY_RUN:-0}"
ENV_FILE="${ENV_FILE:-}"
MAX_RETRIES="${MAX_RETRIES:-3}"
RETRY_BACKOFF="${RETRY_BACKOFF:-30 120 300}"   # seconds between attempts; space-separated
HEARTBEAT_INTERVAL="${HEARTBEAT_INTERVAL:-60}" # 0 to disable

STATE_DIR="$BATCH_DIR/state"
KEY_STATE_DIR="$STATE_DIR/keys"

mkdir -p "$LOGS_DIR" "$DONE_DIR" "$KEY_STATE_DIR"
: > "$DRIVER_LOG"
[[ -f "$SUMMARY_TSV" ]] || printf 'project\tfile\trun_id\tstatus\thypotheses\telapsed_s\tlog\n' > "$SUMMARY_TSV"

# Tee driver stdout/stderr into $DRIVER_LOG.
exec > >(tee -a "$DRIVER_LOG") 2>&1

log()  { printf '[%s] %s\n' "$(date -u +%H:%M:%S)" "$*"; }
die()  { log "FATAL: $*"; exit 1; }

# -----------------------------------------------------------------------------
# cleanup / signals
# -----------------------------------------------------------------------------
INTERRUPTED=0
on_signal() {
    INTERRUPTED=1
    log "interrupt received; stopping background jobs..."
    # kill direct children; they'll cascade to their own children (python, docker)
    pkill -TERM -P $$ 2>/dev/null || true
}
on_exit() {
    # graceful: wait briefly for children to die after a signal
    if (( INTERRUPTED )); then
        sleep 2
        pkill -KILL -P $$ 2>/dev/null || true
    fi
}
trap on_signal INT TERM
trap on_exit EXIT

# -----------------------------------------------------------------------------
# env / prerequisites
# -----------------------------------------------------------------------------
if [[ -n "$ENV_FILE" ]]; then
    [[ -f "$ENV_FILE" ]] || die "ENV_FILE '$ENV_FILE' not found"
    # shellcheck disable=SC1090
    set -a; source "$ENV_FILE"; set +a
    log "sourced env file: $ENV_FILE"
fi

command -v docker >/dev/null || die "docker not on PATH"
command -v python >/dev/null || die "python not on PATH"
python -c 'import revelio' 2>/dev/null || die "cannot import revelio (activate your venv?)"

# -----------------------------------------------------------------------------
# helpers
# -----------------------------------------------------------------------------
# strip ANSI escape codes from a log line
strip_ansi() { sed -E 's/\x1B\[[0-9;]*[mK]//g'; }

# safe filename component (replace path separators and unusual chars)
safe_name() { printf '%s' "$1" | tr '/\\: ' '____'; }

extract_run_dir() {
    # detect.py prints: "Run output directory: <path>"
    local log_file="$1"
    strip_ansi < "$log_file" \
        | awk '/Run output directory:/ { print $NF }' \
        | tail -n 1
}

count_hypotheses() {
    local run_dir="$1"
    local hyp="$run_dir/hypotheses.json"
    [[ -f "$hyp" ]] || { echo ""; return; }
    python - "$hyp" <<'PY' 2>/dev/null || echo "?"
import json, sys
try:
    with open(sys.argv[1]) as f:
        data = json.load(f)
    print(len(data.get("hypotheses", [])))
except Exception:
    print("?")
PY
}

# ---- failure classification & key budget tracking --------------------------
# Look at the tail of a per-pair log and categorize the failure. Categories:
#   quota     API credit/quota exhausted (treat the key as dead)
#   auth      bad/revoked key           (treat the key as dead)
#   transient rate limit / 5xx / timeout / reset  (worth retrying)
#   other     unknown (don't retry blindly)
classify_failure() {
    local log_file="$1"
    [[ -s "$log_file" ]] || { echo other; return; }
    local t
    t="$(tail -n 400 "$log_file" 2>/dev/null | tr -d '\r')"
    if grep -qE -i 'insufficient_quota|credit balance is too low|exceeded your (monthly|current) quota|quota.?exceeded|\bbilling\b|payment required|\b402\b|upstream_rate_limit_exceeded|out of credits|workspace api usage limits?|reached your (specified )?(monthly|daily|workspace) (usage|spend|api) limit|usage limit (has been )?(reached|exceeded)|spend limit|monthly budget|budget (exceeded|exhausted)' <<<"$t"; then
        echo quota; return
    fi
    if grep -qE -i 'invalid[_ -]?api[_ -]?key|authentication[_ ]?error|incorrect api key|\b401\b.*unauthorized|authenticationerror|permissiondeniederror|\b403\b.*forbidden' <<<"$t"; then
        echo auth; return
    fi
    if grep -qE -i 'rate[_ -]?limit|\b429\b|ratelimiterror|overloaded|apiconnectionerror|apitimeouterror|readtimeout|connecttimeout|connectionreseterror|remotedisconnected|connection aborted|connection reset|bad gateway|service unavailable|gateway timeout|\b50[234]\b' <<<"$t"; then
        echo transient; return
    fi
    echo other
}

mark_key_dead() {
    local env="$1" reason="$2"
    local f="$KEY_STATE_DIR/$env.dead"
    if [[ ! -e "$f" ]]; then
        printf '%s %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$reason" > "$f"
        log "[key:$env] MARKED DEAD (reason=$reason) - future jobs using this key will be skipped"
    fi
    if all_keys_dead; then
        log "FATAL: every API key in jobs.tsv is dead; stopping batch"
        INTERRUPTED=1
        pkill -TERM -P $$ 2>/dev/null || true
    fi
}

key_is_dead() {
    [[ -e "$KEY_STATE_DIR/$1.dead" ]]
}

all_keys_dead() {
    # every distinct env var appearing in jobs.tsv must have a .dead marker
    local env
    while IFS=$'\t' read -r _ _ _ env _; do
        [[ -z "$env" || "$env" =~ ^# ]] && continue
        [[ -e "$KEY_STATE_DIR/$env.dead" ]] || return 1
    done < <(grep -vE '^\s*(#|$)' "$JOBS_TSV")
    return 0
}

# Collect distinct api_key_env names from the TSV and verify they resolve.
distinct_key_envs() {
    awk -F'\t' '
        /^[[:space:]]*(#|$)/ {next}
        NF >= 4 && $4 != "" { if (!seen[$4]++) print $4 }
    ' "$JOBS_TSV"
}

preflight_keys() {
    local env val missing=0 total=0
    while read -r env; do
        total=$(( total + 1 ))
        val="${!env:-}"
        if [[ -z "$val" ]]; then
            log "WARN: env var \$$env is empty or unset (jobs using it will be skipped)"
            missing=$(( missing + 1 ))
        else
            log "preflight: \$$env is set (${#val} chars)"
        fi
    done < <(distinct_key_envs)
    if (( total == 0 )); then
        die "no jobs found in $JOBS_TSV"
    fi
    if (( missing == total )); then
        die "none of the $total distinct api_key_env vars in the TSV are set"
    fi
}

# ---- heartbeat -------------------------------------------------------------
heartbeat_loop() {
    local interval="$1"
    while sleep "$interval"; do
        [[ -f "$SUMMARY_TSV" ]] || continue
        local ok fail dead missing dead_keys f
        ok=$(awk -F'\t' 'NR>1 && $4=="OK"          {c++} END{print c+0}' "$SUMMARY_TSV")
        fail=$(awk -F'\t' 'NR>1 && $4 ~ /^FAIL:/    {c++} END{print c+0}' "$SUMMARY_TSV")
        dead=$(awk -F'\t' 'NR>1 && $4=="KEY_DEAD"   {c++} END{print c+0}' "$SUMMARY_TSV")
        missing=$(awk -F'\t' 'NR>1 && $4=="MISSING_KEY" {c++} END{print c+0}' "$SUMMARY_TSV")
        dead_keys=""
        for f in "$KEY_STATE_DIR"/*.dead; do
            [[ -e "$f" ]] || continue
            dead_keys+="$(basename "$f" .dead),"
        done
        dead_keys="${dead_keys%,}"
        log "[heartbeat] ok=$ok fail=$fail key_dead=$dead missing=$missing dead_keys=[${dead_keys:-none}]"
    done
}

# Run one (project, file) pair. Never exits the script on failure.
run_one_file() {
    local name="$1" image="$2" model="$3" api_key_env="$4"
    local extra_args="$5" rel_file="$6"

    local key
    key="$(safe_name "$name")__$(safe_name "$rel_file")"
    local log_file="$LOGS_DIR/${key}.log"
    local done_file="$DONE_DIR/${key}"

    if [[ "$RESUME" == "1" && -f "$done_file" ]]; then
        log "[$name :: $rel_file] SKIP (resume, already done)"
        return 0
    fi

    if key_is_dead "$api_key_env"; then
        log "[$name :: $rel_file] SKIP: key \$$api_key_env marked dead"
        printf '%s\t%s\t\tKEY_DEAD\t\t0\t%s\n' "$name" "$rel_file" "$log_file" >> "$SUMMARY_TSV"
        return 0
    fi

    local api_key="${!api_key_env:-}"
    if [[ -z "$api_key" ]]; then
        log "[$name :: $rel_file] SKIP: env var \$$api_key_env is empty"
        printf '%s\t%s\t\tMISSING_KEY\t\t0\t%s\n' "$name" "$rel_file" "$log_file" >> "$SUMMARY_TSV"
        return 0
    fi

    local -a cmd=(
        python -m revelio.run.detect
        --arvo             "$image"
        --hypothesis-model "$model"
        --pipeline         scan_filter
        --target-file      "$rel_file"
        --max-workers      "$MAX_WORKERS"
        --top-n            "$TOP_N"
    )
    # shellcheck disable=SC2206
    [[ -n "$extra_args" ]] && cmd+=( $extra_args )

    log "[$name :: $rel_file] starting (model=$model, log=$log_file)"
    if [[ "$DRY_RUN" == "1" ]]; then
        log "[$name :: $rel_file] DRY_RUN cmd: MODEL_API_KEY=\$$api_key_env ${cmd[*]}"
        return 0
    fi

    local start=$SECONDS
    local rc=0
    local category=""
    local attempt=1
    local -a backoffs
    # shellcheck disable=SC2206
    backoffs=( $RETRY_BACKOFF )
    local max_attempts=$(( MAX_RETRIES + 1 ))

    while (( attempt <= max_attempts )); do
        if (( INTERRUPTED )); then rc=130; break; fi
        # re-check key deadness before each attempt - a sibling project may have
        # just marked this key dead.
        if key_is_dead "$api_key_env"; then
            log "[$name :: $rel_file] aborting: \$$api_key_env became dead mid-retry"
            rc=${rc:-1}
            category="keydead"
            break
        fi

        rc=0
        MODEL_API_KEY="$api_key" "${cmd[@]}" > "$log_file" 2>&1 || rc=$?
        if (( rc == 0 )); then
            break
        fi
        category=$(classify_failure "$log_file")
        log "[$name :: $rel_file] attempt $attempt/$max_attempts FAILED rc=$rc category=$category"

        case "$category" in
            quota|auth)
                mark_key_dead "$api_key_env" "$category"
                break
                ;;
            transient)
                if (( attempt < max_attempts )); then
                    local idx=$(( attempt - 1 ))
                    local wait_s="${backoffs[$idx]:-300}"
                    log "[$name :: $rel_file] transient; sleeping ${wait_s}s before retry"
                    sleep "$wait_s" &
                    wait "$!" 2>/dev/null || true
                fi
                ;;
            *)
                break
                ;;
        esac
        attempt=$(( attempt + 1 ))
    done

    local elapsed=$(( SECONDS - start ))

    local run_dir run_id hyp_count status
    run_dir="$(extract_run_dir "$log_file" || true)"
    run_id="${run_dir##*/}"
    hyp_count="$(count_hypotheses "$run_dir" 2>/dev/null || true)"

    if (( rc == 0 )); then
        status="OK"
        touch "$done_file"
        log "[$name :: $rel_file] OK in ${elapsed}s  run=${run_id:-?}  hypotheses=${hyp_count:-?}"
    else
        case "$category" in
            quota|auth|transient|keydead) status="FAIL:$category" ;;
            *)                             status="FAIL:rc_$rc"    ;;
        esac
        log "[$name :: $rel_file] $status after ${attempt} attempt(s), ${elapsed}s  (see $log_file)"
    fi

    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
        "$name" "$rel_file" "${run_id:-}" "$status" "${hyp_count:-}" "$elapsed" "$log_file" \
        >> "$SUMMARY_TSV"
}

# Run all files for one project (backgrounded from the main loop).
run_one_project() {
    local name="$1" image="$2" model="$3" api_key_env="$4"
    local extra_args="$5" files_file="$6"

    if [[ ! -f "$files_file" ]]; then
        # resolve relative to the jobs.tsv dir
        if [[ -f "$JOBS_DIR/$files_file" ]]; then
            files_file="$JOBS_DIR/$files_file"
        else
            log "[$name] SKIP project: files file '$files_file' not found"
            return 0
        fi
    fi

    if [[ -z "${!api_key_env:-}" ]]; then
        log "[$name] SKIP project: env var \$$api_key_env is not set"
        return 0
    fi

    # strip comments/blank lines once
    local -a files=()
    while IFS= read -r line; do
        line="${line%$'\r'}"                  # strip CR if CRLF
        [[ -z "$line" || "$line" =~ ^[[:space:]]*# ]] && continue
        files+=("$line")
    done < "$files_file"

    log "[$name] project start: image=$image model=$model files=${#files[@]}"

    if [[ "$FILES_CONCURRENCY" -le 1 ]]; then
        for f in "${files[@]}"; do
            (( INTERRUPTED )) && break
            if key_is_dead "$api_key_env"; then
                log "[$name] key \$$api_key_env dead; marking remaining files KEY_DEAD"
                printf '%s\t%s\t\tKEY_DEAD\t\t0\t\n' "$name" "$f" >> "$SUMMARY_TSV"
                continue
            fi
            run_one_file "$name" "$image" "$model" "$api_key_env" \
                         "$extra_args" "$f"
        done
    else
        local active=0
        for f in "${files[@]}"; do
            (( INTERRUPTED )) && break
            if key_is_dead "$api_key_env"; then
                printf '%s\t%s\t\tKEY_DEAD\t\t0\t\n' "$name" "$f" >> "$SUMMARY_TSV"
                continue
            fi
            run_one_file "$name" "$image" "$model" "$api_key_env" \
                         "$extra_args" "$f" &
            active=$(( active + 1 ))
            if (( active >= FILES_CONCURRENCY )); then
                wait -n 2>/dev/null || true
                active=$(( active - 1 ))
            fi
        done
        wait
    fi

    log "[$name] project done"
}

# -----------------------------------------------------------------------------
# main
# -----------------------------------------------------------------------------
log "=== batch scan_filter starting ==="
log "jobs        : $JOBS_TSV"
log "batch dir   : $BATCH_DIR"
log "PROJECT_CONCURRENCY=$PROJECT_CONCURRENCY FILES_CONCURRENCY=$FILES_CONCURRENCY"
log "MAX_WORKERS=$MAX_WORKERS TOP_N=$TOP_N"
log "RESUME=$RESUME DRY_RUN=$DRY_RUN"
log "MAX_RETRIES=$MAX_RETRIES RETRY_BACKOFF='$RETRY_BACKOFF' HEARTBEAT_INTERVAL=$HEARTBEAT_INTERVAL"

preflight_keys

HEARTBEAT_PID=""
if (( HEARTBEAT_INTERVAL > 0 )); then
    heartbeat_loop "$HEARTBEAT_INTERVAL" &
    HEARTBEAT_PID=$!
    log "heartbeat started (pid=$HEARTBEAT_PID, every ${HEARTBEAT_INTERVAL}s)"
fi

active_projects=0
declare -a PIDS=()

# Read jobs.tsv: each line is one project.
while IFS= read -r rawline || [[ -n "$rawline" ]]; do
    rawline="${rawline%$'\r'}"
    [[ -z "$rawline" || "$rawline" =~ ^[[:space:]]*# ]] && continue

    # split on tabs; up to 7 columns
    IFS=$'\t' read -r name image model api_key_env files_file extra_args <<<"$rawline"

    name="${name:-}"; image="${image:-}"; model="${model:-}"
    api_key_env="${api_key_env:-}"; files_file="${files_file:-}"
    extra_args="${extra_args:-}"

    if [[ -z "$name" || -z "$image" || -z "$model" || -z "$api_key_env" || -z "$files_file" ]]; then
        log "WARN: bad row (need 5+ tab-separated columns): $rawline"
        continue
    fi

    # throttle projects
    while (( active_projects >= PROJECT_CONCURRENCY )); do
        if wait -n 2>/dev/null; then :; fi
        active_projects=$(( active_projects - 1 ))
    done

    run_one_project "$name" "$image" "$model" "$api_key_env" \
                    "$extra_args" "$files_file" &
    PIDS+=($!)
    active_projects=$(( active_projects + 1 ))
done < "$JOBS_TSV"

for pid in "${PIDS[@]+"${PIDS[@]}"}"; do
    wait "$pid" 2>/dev/null || true
done

if [[ -n "$HEARTBEAT_PID" ]]; then
    kill "$HEARTBEAT_PID" 2>/dev/null || true
    wait "$HEARTBEAT_PID" 2>/dev/null || true
fi

log "=== batch done ==="
log "summary: $SUMMARY_TSV"
# final tallies by status
awk -F'\t' 'NR>1 {c[$4]++} END{for(k in c) printf("  %-18s %d\n",k,c[k])}' "$SUMMARY_TSV" \
    | sort | sed 's/^/[totals]/'
if [[ -d "$KEY_STATE_DIR" ]]; then
    dead_total=$(find "$KEY_STATE_DIR" -maxdepth 1 -name '*.dead' | wc -l)
    if (( dead_total > 0 )); then
        log "dead keys this run:"
        for f in "$KEY_STATE_DIR"/*.dead; do
            [[ -e "$f" ]] || continue
            log "  \$$(basename "$f" .dead) -> $(cat "$f")"
        done
    fi
fi
log "per-pair table:"
if command -v column >/dev/null; then
    column -t -s $'\t' "$SUMMARY_TSV" | sed 's/^/    /'
else
    sed 's/^/    /' "$SUMMARY_TSV"
fi
