# `scripts/batch_scan_filter/`

Batch runner for the `scan_filter` vul-agent pipeline across many
`(project, file)` pairs. Each row in `jobs.tsv` selects a Docker image,
a model, an API-key env var, and a list of target files; the driver
script `scripts/batch_scan_filter.sh` invokes
`python -m vulagent.run.detect --pipeline scan_filter --target-file <f>`
once per pair, with retries, per-key failure tracking, and a resume
mode so long batches survive transient failures and key quota caps.

## Layout

```
scripts/
├── batch_scan_filter.sh           # the runner
└── batch_scan_filter/
    ├── README.md                  # (this file)
    ├── .env.example               # template for API keys (copy to .env)
    ├── .env                       # REAL keys; .gitignored
    ├── jobs.tsv                   # default 8-project job list
    ├── jobs.poppler-retry.tsv     # example: reroute one project to a backup key
    └── files.<project>.txt        # target-file lists (10 files/project)
```

## Setup

1. **Copy the env template and fill in keys** (`.env` is gitignored):

   ```bash
   cp scripts/batch_scan_filter/.env.example scripts/batch_scan_filter/.env
   chmod 600 scripts/batch_scan_filter/.env
   # edit the file and replace the sk-ant-... / sk-or-... placeholders
   ```

2. **Probe keys before a long run** (optional but recommended, especially
   after rotating keys):

   ```bash
   python scripts/batch_scan_filter/probe_keys.py   # see note below
   ```

   There is also a standalone probe script at `/tmp/probe_keys.py` used
   during development; if you want it promoted into the tree, move it
   here.

3. **Make sure the Docker images referenced in `jobs.tsv` exist locally.**
   Missing images produce fast `FAIL:rc_1` rows (docker 125 "Unable to
   find image locally"); the runner will not pull them automatically.

   ```bash
   docker images --format '{{.Repository}}:{{.Tag}}' | grep ^vulagent/
   ```

## jobs.tsv schema

Tab-separated. One row per project. Header is comments only; parsing is
by position.

| col | field          | meaning                                                         |
|----:|----------------|-----------------------------------------------------------------|
| 1   | `name`         | short tag used in log filenames (e.g. `openssl`)                |
| 2   | `image`        | Docker image, e.g. `vulagent/openssl:latest`                    |
| 3   | `model`        | LiteLLM model slug passed to `--model`                          |
| 4   | `api_key_env`  | NAME of an env var holding the key (not the key itself)         |
| 5   | `files_file`   | text file with one target path per line (`#` comments OK)       |
| 6   | `filter_model` | optional, overrides `--filter-model` per project                |
| 7   | `extra_args`   | optional, appended verbatim to the `detect.py` CLI              |

Rows may share the same `api_key_env` to reuse one key across multiple
projects. Projects sharing a key will serialize on that key's rate
limit if run concurrently — pick `PROJECT_CONCURRENCY` to match the
number of *distinct* keys, not rows. For example, with 3 distinct
`ANTHROPIC_KEY_1 / ANTHROPIC_KEY_2 / OPENROUTER_KEY` env vars across 8
projects, the sweet spot is `PROJECT_CONCURRENCY=3`.

### Known-good model slugs

| provider   | slug                                        | used by (default)           |
|------------|---------------------------------------------|-----------------------------|
| Anthropic  | `anthropic/claude-haiku-4-5`                | 6 of 8 projects             |
| OpenRouter | `openrouter/anthropic/claude-haiku-4.5`     | libheif, sleuthkit          |

> OpenRouter's canonical slug uses a dot (`4.5`), not a hyphen. The
> LiteLLM form is `openrouter/anthropic/claude-haiku-4.5`.

## Target-file lists

`files.<project>.txt` lists the 10 highest-risk files per project,
picked by an OSS-Fuzz-coverage-driven heuristic: low-coverage C/C++
files on fuzzed reach paths, weighted by uncovered-line count and by
path keywords known to correlate with memory safety risk (parsers,
decoders, splash renderers, ASN.1, etc.). Each file begins with a
commented header describing the ranking metadata.

Format: `#` comments and blank lines are ignored. Everything else is
one target path per line, expressed relative to `/src/` inside the
project's container (same form `--target-file` expects).

## Running

### Default full batch

```bash
PROJECT_CONCURRENCY=3 \
  ENV_FILE=scripts/batch_scan_filter/.env \
  scripts/batch_scan_filter.sh scripts/batch_scan_filter/jobs.tsv
```

Detach for long runs (hours):

```bash
screen -S vul-batch
# inside the screen:
PROJECT_CONCURRENCY=3 ENV_FILE=scripts/batch_scan_filter/.env \
  scripts/batch_scan_filter.sh scripts/batch_scan_filter/jobs.tsv
# Ctrl-A d to detach; `screen -r vul-batch` to reattach
```

### Dry-run (print commands, don't execute)

```bash
DRY_RUN=1 ENV_FILE=scripts/batch_scan_filter/.env \
  scripts/batch_scan_filter.sh scripts/batch_scan_filter/jobs.tsv
```

### Resume after a failure

`RESUME=1` skips any `(project, file)` pair that already has a sentinel
in `$BATCH_DIR/done/`. Sentinels are only created for `OK` outcomes, so
resume always retries failed/incomplete pairs and never re-runs work
that already succeeded.

```bash
RESUME=1 PROJECT_CONCURRENCY=3 \
  ENV_FILE=scripts/batch_scan_filter/.env \
  BATCH_DIR=batch/batch_20260417-051220 \
  scripts/batch_scan_filter.sh scripts/batch_scan_filter/jobs.tsv
```

### Reroute one project to a backup key

When one key hits a workspace spend cap mid-batch, rather than waiting
for the cap to reset, copy just the affected row(s) into a one-shot
TSV with a different `api_key_env` (and matching `model` if the
provider differs) and run with `RESUME=1` pointing at the same
`BATCH_DIR`. Example: `jobs.poppler-retry.tsv` shows poppler pointed at
`OPENROUTER_KEY` instead of `ANTHROPIC_KEY_1`.

```bash
RESUME=1 PROJECT_CONCURRENCY=1 \
  ENV_FILE=scripts/batch_scan_filter/.env \
  BATCH_DIR=batch/batch_20260417-051220 \
  scripts/batch_scan_filter.sh scripts/batch_scan_filter/jobs.poppler-retry.tsv
```

## Environment knobs

All optional. Defaults in parentheses.

| var                  | meaning                                                                           |
|----------------------|-----------------------------------------------------------------------------------|
| `PROJECT_CONCURRENCY`| max projects running at once (8). Set to # of distinct API keys in `jobs.tsv`.    |
| `FILES_CONCURRENCY`  | files per project running at once (1). Keep at 1 to avoid rate-limiting a key.    |
| `MAX_WORKERS`        | passed as `--max-workers` to detect.py (4)                                        |
| `FILTER_WORKERS`     | passed as `--filter-workers` to detect.py (4)                                     |
| `TOP_N`              | passed as `--top-n` to detect.py (10)                                             |
| `BATCH_DIR`          | output dir (default `batch/batch_<timestamp>`; reuse same dir for `RESUME=1`)     |
| `RESUME`             | `1` to skip pairs with OK sentinels in `done/` (0)                                |
| `DRY_RUN`            | `1` to print commands without executing (0)                                       |
| `ENV_FILE`           | path to a KEY=VALUE file to source for API keys                                   |
| `MAX_RETRIES`        | retry count for transient failures (3)                                            |
| `RETRY_BACKOFF`      | space-separated sleeps in seconds between retries (`"30 120 300"`)                |
| `HEARTBEAT_INTERVAL` | seconds between progress lines; `0` disables (60)                                 |

## Error handling

Each failed invocation is classified by pattern-matching the tail of
its log:

| class       | regex signals                                                                                      | action                                                                   |
|-------------|---------------------------------------------------------------------------------------------------|--------------------------------------------------------------------------|
| `quota`     | `insufficient_quota`, `credit balance is too low`, `quota exceeded`, `workspace api usage limits`, `spend limit`, `budget exceeded`, `\b402\b`, etc. | **mark key dead** (no retry); siblings using same key skip with `KEY_DEAD` |
| `auth`      | `invalid api key`, `401`, `403`, `permission denied`, `authentication error`                       | mark key dead (no retry)                                                 |
| `transient` | `rate limit`, `429`, `503/504`, `overloaded`, `timeout`, `connection reset`                        | retry up to `MAX_RETRIES` with `RETRY_BACKOFF` delays                    |
| `other`     | anything else (e.g. docker 125, internal exceptions)                                               | record as `FAIL:rc_<n>`; do not retry                                    |

If *every* distinct `api_key_env` in `jobs.tsv` gets marked dead, the
whole batch aborts (rather than burning through the rest of the queue
with known-broken keys). Per-run state lives under
`$BATCH_DIR/state/keys/<env>.dead` so parallel projects see the disable
immediately.

A heartbeat line is emitted every `HEARTBEAT_INTERVAL` seconds with
cumulative counts (`ok`, `fail`, `key_dead`, `missing`) and the current
dead-key list — useful when files take many minutes each and the
terminal would otherwise look frozen.

## Outputs

```
batch/batch_<YYYYMMDD-HHMMSS>/
├── batch.log                          # driver's own stdout/stderr
├── logs/<name>__<file>.log            # one log per (project, file) invocation
├── done/<name>__<file>                # sentinel created on OK (used by RESUME)
├── state/keys/<env>.dead              # appears if a key is disabled mid-run
└── summary.tsv                        # tabular ledger; one row per attempt
```

`summary.tsv` columns:

```
project  file  run_id  status  hypothesis_count  elapsed_s  log_path
```

`status` values:
`OK | FAIL:quota | FAIL:auth | FAIL:transient | FAIL:rc_<n> | KEY_DEAD | MISSING_KEY`

The actual pipeline artifacts (hypothesis JSON, PoCs, etc.) are written
by `detect.py` into the usual `output/<image>_<model>_<timestamp>/`
tree, not under `$BATCH_DIR`. The batch ledger's `log_path` column
points to the runner's log which itself records the run directory.

## Troubleshooting

**All poppler rows fail in 3–4 s with `FAIL:rc_1`.**
The Docker image is missing locally. Check with
`docker images | grep vulagent/<project>`. Build or pull, then rerun
with `RESUME=1` + the same `BATCH_DIR`.

**A key hits a workspace spend cap mid-batch.**
The error phrasing is `"workspace api usage limits"` (classified as
`quota`, key marked dead for the rest of the run). To finish the
project before the cap resets, write a small one-row TSV pointing at a
backup `api_key_env` (and matching `model`, e.g. `openrouter/...`) and
rerun with `RESUME=1` + the same `BATCH_DIR`. See
`jobs.poppler-retry.tsv` for a worked example.

**Heartbeat sits at the same counts for minutes.**
That's expected. Counts are per *file*, not per hypothesis; each file
runs 20–70 hypothesis classification passes and can take 3–15 min. To
see what's actually happening, tail the per-file log:

```bash
tail -f batch/batch_.../logs/<project>__<file>.log
```

**`summary.tsv` has both FAIL and OK rows for the same file.**
Normal after a resume — the file shows up once per attempt, and the
later `OK` row is the authoritative one. The `done/` sentinel is the
source of truth for `RESUME=1`; it only exists if the latest attempt
succeeded.
