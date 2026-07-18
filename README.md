# Revelio

<img width="354" height="349" alt="D39BDFFF-F4F6-45B1-B69A-AE60A9F6C919_1_201_a" src="https://github.com/user-attachments/assets/80249d46-3f0a-4e17-94a6-8bab5f2b426b" />


A trustworthy and precise vulnerability detection AI agent that discovers memory safety related software vulnerabilities and validates them through automated PoV testing.

- **Discovers vulnerabilities** through code review
- **Validates findings** by building and running PoV inputs
- **Generates reports** with detailed vulnerability information and reproduction steps

## Architecture

### Pipeline Stages

1. **ScanFilterOrchestrator** — per-file multi-pass LLM analysis, classification/dedup, and Docker sub-agent filtering to produce ranked hypotheses
2. **PoCBuilderAgent** — for each hypothesis, discovers which fuzz targets link the relevant function (`arvo targets <sym>`), then generates a PoV for each matching target. The `validate` tool automatically tests the PoV against all available sanitizers (asan, ubsan, msan). Stops on first confirmed crash.
3. **ReporterAgent** — writes a final bug report with vulnerability details and reproduction steps

### Pipeline

```
detect.py  --arvo / --project
                │
                └── ScanFilterOrchestrator (per file)
                      ├── Initial Hypothesis Proposal: extract functions (tree-sitter),
                      │   summarize file content, synthesize hypotheses (focused passes)
                      ├── In-scope Hypotheses: sanitizer-aware triage (LLM classification)
                      ├── Merged Hypotheses: deduplicate root causes
                      ├── Reachability-Annotated Hypotheses: independent static filtering
                      │   (Docker sub-agent)
                      ├── Ranked Hypothesis Queue: rank for PoV confirmation
                      └── MultiAgentOrchestrator
                            ├── PoCBuilderAgent × N (uses validate tool)
                            └── ReporterAgent × N
```

The pipeline uses three separate model tiers:
- **`--model`** — cheap/fast model for the proposal + triage/dedup hypothesis generation (e.g., Haiku)
- **`--filter-model`** — mid-tier model for the independent static filtering sub-agent (e.g., Sonnet)
- **`--pov-model`** — strongest model for PoV building + validation/report (e.g., Opus)

## Quick Start

### Installation

```bash
git clone <repo-url>
cd revelio
```

**conda env**

```bash
conda create -n revelio python=3.12 -y
conda activate revelio
pip install -e .
```

### Configuration

Create a `.env` file in the project root (or set environment variables):

```bash
# Required: at least one model + its API key
MODEL_NAME=anthropic/claude-opus-4-6
ANTHROPIC_API_KEY=sk-ant-...

# Or use Gemini
# MODEL_NAME=gemini/gemini-2.5-pro
# GEMINI_API_KEY=AIza...
```

## Building OSS-Fuzz Docker Images

`scripts/prepare_ossfuzz_project.sh` builds any [OSS-Fuzz](https://github.com/google/oss-fuzz) project into a revelio-ready Docker image with the same interface as [ARVO](https://github.com/n132/ARVO) images.

```bash
scripts/prepare_ossfuzz_project.sh openssl                           # single project
scripts/prepare_ossfuzz_project.sh openssl assimp curl               # multiple projects
scripts/prepare_ossfuzz_project.sh --sanitizers asan,ubsan openssl   # skip MSan
scripts/prepare_ossfuzz_project.sh --oss-fuzz-dir /data/oss-fuzz openssl
```

The script clones/updates oss-fuzz, builds fuzzers with each sanitizer via `infra/helper.py build_fuzzers`, packages them into a single Docker image, and cleans it for zero-day detection. Sanitizers that fail to build are skipped automatically.

The resulting `revelio/<project>:latest` image contains:

```
/src/<project>/              source code (from the gcr.io/oss-fuzz/<project> base image)
/out/asan/<fuzzer_binaries>  AddressSanitizer builds
/out/ubsan/<fuzzer_binaries> UndefinedBehaviorSanitizer builds
/out/msan/<fuzzer_binaries>  MemorySanitizer builds
/usr/bin/arvo                fuzzer runner script (scripts/arvo_ossfuzz)
```

Re-run the script to pick up upstream source code changes.

### The `arvo` script

`scripts/arvo_ossfuzz` is installed at `/usr/bin/arvo` inside the container. It provides the same interface as ARVO images, extended for multi-sanitizer and multi-target support:

```bash
arvo                         # run default fuzzer with /tmp/poc (SANITIZER=asan)
arvo list                    # list fuzz targets for current SANITIZER
arvo list --all              # list fuzz targets across all sanitizers
arvo run <fuzzer> [poc]      # run a specific fuzzer (default poc: /tmp/poc)
arvo targets <symbol>        # find which fuzz targets link a given function (nm lookup)
arvo compile                 # recompile the project
SANITIZER=ubsan arvo         # switch sanitizer
```

`SANITIZER` env var (default: `asan`) selects which `/out/<sanitizer>/` build to use. `DEFAULT_FUZZER` env var overrides auto-detection when multiple targets exist. Standard ASAN/MSAN/UBSAN env vars are exported automatically.

The orchestrator uses `arvo targets <function>` to match hypotheses to reachable fuzz targets before launching the PoV builder. The validate tool uses `SANITIZER=` to test PoVs against all available sanitizers.

### Verifying the image

```bash
docker run --rm revelio/openssl:latest arvo list --all
docker run --rm -v /path/to/poc:/tmp/poc:ro revelio/openssl:latest arvo run openssl_fuzzer
docker run --rm -v /path/to/poc:/tmp/poc:ro -e SANITIZER=ubsan revelio/openssl:latest arvo run openssl_fuzzer
```

## Revelio for Vulnerability Detection

### ARVO Targets

[ARVO](https://github.com/n132/ARVO) provides pre-built Docker images with fuzzing infrastructure.

```bash
python -m revelio.run.detect \
    --arvo n132/arvo:42470801-vul \
    --model anthropic/claude-opus-4-6

# Scan a specific file only
python -m revelio.run.detect \
    --arvo n132/arvo:42470801-vul \
    --model anthropic/claude-opus-4-6 \
    --target-file ffmpeg/tools/target_dec_fuzzer.c
```

> **Note:** `arvo:xxx-vul-clean` images are produced using `python -m revelio.run.clean_arvo`
> to remove pre-existing PoVs, crashers, and seed corpus from ARVO-vul images.

### OSS-Fuzz Targets

For OSS-Fuzz Docker images built with the steps above:

```bash
python -m revelio.run.detect \
    --arvo revelio/assimp:latest \
    --model anthropic/claude-opus-4-6
```

### Custom Projects

```bash
python -m revelio.run.detect \
    --project ./my-project \
    --model anthropic/claude-opus-4-6 \
    --target-file src/parser.c
```

Use `--docker-image` to specify a custom Docker base image (default: `revelio/memcheck:latest`).

### Resuming from saved hypotheses

The scan_filter stage saves hypotheses to `output/<run_id>/hypotheses.json`. You can skip the scan stage and go straight to PoV generation:

```bash
python -m revelio.run.detect \
    --arvo revelio/assimp:latest \
    --hypotheses-file output/<run_id>/hypotheses.json \
    --model anthropic/claude-opus-4-6
```

### Key Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--target-file`, `-t` | — | Restrict scan to a single file |
| `--max-workers` | `4` | Parallel workers for hypothesis generation |
| `--top-n` | `10` | Number of top hypotheses to pursue |
| `--max-poc-attempts` | `3` | Max validation attempts per hypothesis (PoCBuilder's `validate` tool calls) |
| `--keep-container` | `false` | Keep Docker container after run (for debugging) |
| `--verbose`, `-v` | `false` | Show DEBUG-level logs (raw Docker commands, per-file cleanup steps, etc.) |
| `--agents-config-dir` | built-in | Custom directory for per-agent YAML configs |
| `--filter-model` | Sonnet 4.6 | Model for the independent static filtering sub-agent |
| `--filter-workers` | `4` | Parallel workers for sub-agent filtering |
| `--pov-model` | same as `--model` | Model for PoV builder/reporter agents |
| `--max-functions` | `50` | Max functions to analyze per file in scan_filter |
| `--agent-step-limit` | `20` | Max steps per scan_filter sub-agent |
| `--agent-cost-limit` | `2.0` | Max cost (USD) per scan_filter sub-agent |
| `--base-url` | — | LiteLLM proxy base URL |
| `--api-key` | `MODEL_API_KEY` | API key for LLM calls |
| `--hypotheses-file` | — | Load pre-generated hypotheses, skip scan stage |

## Environment Variables

### Model Selection

| Variable | Description |
|----------|-------------|
| `MODEL_NAME` | Default model name, e.g. `anthropic/claude-opus-4-6`, `gemini/gemini-2.5-pro`. Always include the provider prefix. Can be overridden with `--model`. |

### API Keys

| Variable | Description |
|----------|-------------|
| `MODEL_API_KEY` | Generic API key passed to litellm. Works for any provider. |
| `MODEL_API_KEYS` | Comma-separated pool of API keys for parallel workers (round-robin assignment). Useful when running multiple workers to avoid rate limits. |
| `ANTHROPIC_API_KEY` | Anthropic API key (used automatically by litellm for `anthropic/*` models) |
| `GEMINI_API_KEY` | Google Gemini API key (used automatically by litellm for `gemini/*` models) |

> **Tip:** You only need the provider-specific key for your chosen model. `MODEL_API_KEY` is an alternative that works across providers via litellm.

### Model Behavior

Temperature and other model parameters are configured **per-agent in YAML configs** (`src/revelio/config/agents/`), not via environment variables:

| Agent | Temperature | Purpose |
|-------|-------------|---------|
| `file_hypothesis.yaml` | 0.4 | Balanced hypothesis generation |
| `poc_builder.yaml` | 1.0 | Creative PoV building + validation |
| `validator.yaml` | 0.0 | Strict crash validation (standalone use) |
| `reporter.yaml` | 0.2 | Consistent report writing |

Above temperatures work for GPT and Claude model series.
For Gemini-3 series there's a community report of using temperature=1.0.

### Cost and Rate Limits

| Variable | Default | Description |
|----------|---------|-------------|
| `GLOBAL_COST_LIMIT` | `0` (disabled) | Maximum total cost in USD across all model calls. The run aborts if exceeded. |
| `GLOBAL_CALL_LIMIT` | `0` (disabled) | Maximum total API calls across all agents. The run aborts if exceeded. |
| `MODEL_RETRY_STOP_AFTER_ATTEMPT` | `10` | Number of retries on transient API errors (uses exponential backoff). |

### Runtime

| Variable | Default | Description |
|----------|---------|-------------|
| `DOCKER_EXECUTABLE` | `docker` | Path to Docker/Podman executable |
| `CONFIG_DIR` | `.` | Override location for YAML config files |
| `SILENT_STARTUP` | unset | If set, suppress the startup banner and cost/call limit messages |

## Outputs

Each run writes to `output/<run_id>/`:

```
output/<run_id>/
├── manifest.json          # Run metadata (target, model, pipeline mode, parameters)
├── events.jsonl           # Append-only event log (JSON Lines)
├── log.txt                # Human-readable timestamped log
├── hypotheses.json        # Saved hypotheses (reusable with --hypotheses-file)
├── trajectory.json        # Aggregated multi-agent trajectories
└── artifacts/
    ├── handoffs/          # Inter-agent data (one JSON per stage + hypothesis)
    │   ├── hypotheses.json
    │   ├── poc_recipe_H01.json
    │   ├── validation_H01.json
    │   └── report_H01.json
    └── deliverables/      # Final outputs (copied from container on success)
        ├── final_report_H01.md
        ├── poc_H01
        └── result_script_H01.py
```

- **`manifest.json`** — records run_id, target, model, pipeline mode, top_n, max_workers
- **`events.jsonl`** — real-time event stream: `run_start`, `agent_start`, `agent_end`, `poc_attempt`, `validation_failed`, `run_success`, etc.
- **`trajectory.json`** — full conversation history for all agents, keyed by agent name
- **`handoffs/`** — structured JSON data passed between pipeline stages
- **`deliverables/`** — the final artifacts: bug report, PoV input file, and PoV generator script (only present when a vulnerability is confirmed)

### Cost Reports

```bash
# Summarize direct API cost plus cache/uncached token-cost estimates
SILENT_STARTUP=1 python tools/cost_report.py output/<run_id>

# Also write output/<run_id>/cost_report.json and cost_report.md
SILENT_STARTUP=1 python tools/cost_report.py output/<run_id> --write
```

The report reads saved `trajectory.json` and `traces/*.json`. For agent
trajectories it can split cost into cached input, uncached input, and output
when Anthropic/LiteLLM usage fields are present. Some scan_filter
proposal/refinement traces currently only save aggregate `cost`/`calls`, so
those stages are included in direct API cost but cannot always be split into
cached/uncached tokens retroactively.

### Validating PoVs

Validate PoVs against ARVO `-fix` images (patched versions):

```bash
python tools/validate_poc.py \
    --run-dir output/<run_id> \
    --poc output/<run_id>/artifacts/deliverables/poc_H01
```

## Project Structure

```
revelio/
├── agents/          # Agent implementations (DefaultAgent)
├── analysis/        # Static C/C++ check analyzer (tree-sitter)
├── artifacts/       # Artifact store (typed, append-only, thread-safe)
├── config/          # YAML configs: agents/, arvo_targets.json
├── environments/    # Execution environments (Docker)
├── models/          # LLM interfaces (LiteLLM, Anthropic)
├── orchestrator/    # Multi-agent pipeline + scan-filter orchestration
├── run/             # CLI entry point (detect.py)
├── tools/           # Agent tools (finish, validate)
└── utils/           # Utility functions
```

## Check Agent Running Trajectories

### Textual TUI for browsing trajectory JSON files

```bash
# TUI trajectory inspector (vim-style keybindings)
python tools/inspector.py output/<run_id>/trajectory.json

# Or browse an entire output directory
python tools/inspector.py output/
```

## Web Trace Viewer

Browse agent run outputs in a web interface:

```bash
python3 website/server.py [--host HOST] [--port PORT] [--output-dir DIR ...]
```

| Option | Default | Description |
|--------|---------|-------------|
| `--host` | `127.0.0.1` | Host to bind (localhost only for security) |
| `--port` | `8877` | Port number |
| `--output-dir` | `output/` | Custom output directories to scan |

**Remote access via SSH tunnel:**

```bash
# On local machine
ssh -L 8877:127.0.0.1:8877 <username>@<server>

# Then open http://localhost:8877
```
