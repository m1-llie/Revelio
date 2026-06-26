# Revelio

<img width="354" height="349" alt="D39BDFFF-F4F6-45B1-B69A-AE60A9F6C919_1_201_a" src="https://github.com/user-attachments/assets/80249d46-3f0a-4e17-94a6-8bab5f2b426b" />


A trustworthy and precise vulnerability detection AI agent that discovers memory safety related software vulnerabilities and validates them through automated PoC testing.

- **Discovers vulnerabilities** through code review
- **Validates findings** by building and running PoC inputs
- **Generates reports** with detailed vulnerability information and reproduction steps

## Architecture

### Pipeline Stages

1. **HypothesisOrchestrator** — enumerates source files, runs `FileHypothesisRunner` per file in parallel, merges and ranks hypotheses by confidence
2. **PoCBuilderAgent** — for each hypothesis, discovers which fuzz targets link the relevant function (`arvo targets <sym>`), then generates a PoC for each matching target. The `validate` tool automatically tests the PoC against all available sanitizers (asan, ubsan, msan). Stops on first confirmed crash.
3. **ReporterAgent** — writes a final bug report with vulnerability details and reproduction steps

### Pipeline Modes

 The `--pipeline` flag controls how far the analysis goes.

`--arvo` or `--project` tells detect.py where the code lives (which Docker image to use).

```
detect.py  --pipeline [file | project | detect | scan_filter | scan_filter_detect]
           --arvo / --project
           --target-file  (required for --pipeline=file)
                │
                ├── pipeline=file ──► FileHypothesisRunner (single file, direct)
                │
                ├── pipeline=project|detect ──► MultiAgentOrchestrator
                │                                   ├── HypothesisOrchestrator
                │                                   │     └── FileHypothesisRunner × N (parallel)
                │                                   ├── PoCBuilderAgent × N  (pipeline=detect only, uses validate tool)
                │                                   └── ReporterAgent × N    (pipeline=detect only)
                │
                └── pipeline=scan_filter|scan_filter_detect
                         ──► ScanFilterOrchestrator (per file)
                               ├── Stage 1: Multi-pass LLM analysis (tree-sitter + focused passes)
                               ├── Stage 2: LLM classification + dedup
                               ├── Stage 3: Docker sub-agent filtering
                               └── (scan_filter_detect only) ──► MultiAgentOrchestrator
                                     ├── PoCBuilderAgent × N (uses validate tool)
                                     └── ReporterAgent × N
```

- **`--pipeline file`** — run hypothesis generation on a single file only
- **`--pipeline project`** — run parallel hypothesis generation on all source files, stop before PoC related steps
- **`--pipeline detect`** (default) — full pipeline: hypotheses → PoC building + validation → report
- **`--pipeline scan_filter`** — multi-pass scan → classify/dedup → Docker sub-agent filter, stop after hypotheses
- **`--pipeline scan_filter_detect`** — scan_filter → PoC building + validation → report

Each `FileHypothesisRunner` wraps a `DefaultAgent` with `file_hypothesis.yaml` config.

The `scan_filter` pipeline uses three separate model tiers:
- **`--model`** — cheap/fast model for Stage 1-2 hypothesis generation (e.g., Haiku)
- **`--filter-model`** — mid-tier model for Stage 3 sub-agent verification (e.g., Sonnet)
- **`--poc-model`** — strongest model for PoC building + validation/report (e.g., Opus, only in `scan_filter_detect`)

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

# Or use OpenAI / Gemini
# MODEL_NAME=openai/gpt-5.2
# OPENAI_API_KEY=sk-proj-...

# MODEL_NAME=gemini/gemini-3-pro-preview
# GEMINI_API_KEY=AIza...

# Or use OpenRouter (any model via openrouter.ai)
# MODEL_NAME=openrouter/google/gemini-2.5-pro
# OPENROUTER_API_KEY=sk-or-...
```

Alternatively, run the interactive setup:

```bash
revelio config setup
```

### Hello World

Test the installation with a simple task (no Docker required):

```bash
revelio -t "List all files in the current directory and describe what they do"
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

The orchestrator uses `arvo targets <function>` to match hypotheses to reachable fuzz targets before launching the PoC builder. The validate tool uses `SANITIZER=` to test PoCs against all available sanitizers.

### Verifying the image

```bash
docker run --rm revelio/openssl:latest arvo list --all
docker run --rm -v /path/to/poc:/tmp/poc:ro revelio/openssl:latest arvo run openssl_fuzzer
docker run --rm -v /path/to/poc:/tmp/poc:ro -e SANITIZER=ubsan revelio/openssl:latest arvo run openssl_fuzzer
```

## Vul-agent for Vulnerability Detection

### ARVO Targets

[ARVO](https://github.com/n132/ARVO) provides pre-built Docker images with fuzzing infrastructure.

```bash
# Full pipeline (default): hypotheses → PoC validation → report
python -m revelio.run.detect \
    --arvo n132/arvo:42470801-vul-clean \
    --model anthropic/claude-opus-4-6

# Parallel hypothesis generation only (no PoC/validation/report)
python -m revelio.run.detect \
    --arvo n132/arvo:42470801-vul-clean \
    --model anthropic/claude-opus-4-6 \
    --pipeline project \
    --max-workers 8

# Single file hypothesis only
python -m revelio.run.detect \
    --arvo n132/arvo:42470801-vul-clean \
    --model anthropic/claude-opus-4-6 \
    --pipeline file \
    --target-file coders/svg.c
```

> **Note:** `arvo:xxx-vul-clean` images are produced using `python -m revelio.run.clean_arvo`
> to remove pre-existing PoCs, crashers, and seed corpus from ARVO-vul images.

### OSS-Fuzz Targets

For OSS-Fuzz Docker images built with the steps above:

```bash
# Full pipeline: scan → hypotheses → PoC → validate → report
python -m revelio.run.detect \
    --arvo revelio/assimp:latest \
    --model anthropic/claude-opus-4-6

# Scan a specific file
python -m revelio.run.detect \
    --arvo revelio/assimp:latest \
    --model anthropic/claude-opus-4-6 \
    --pipeline file \
    --target-file code/AssetLib/FBX/FBXBinaryTokenizer.cpp
```

### Custom Projects

Example: Single file hypothesis on a custom project

```bash
python -m revelio.run.detect \
    --project ./my-project \
    --model anthropic/claude-opus-4-6 \
    --pipeline file \
    --target-file src/parser.c
```

Use `--docker-image` to specify a custom Docker base image (default: `revelio/memcheck:latest`).

### Scan-and-Filter Pipeline

The `scan_filter` pipeline uses a more thorough multi-pass analysis: tree-sitter function parsing, multiple focused LLM passes, LLM-based classification/dedup, and Docker sub-agent verification. It can be run standalone or as the front-end to the full PoC generation pipeline.

#### Standalone scan_and_filter (via detect.py)

```bash
# Scan + classify + dedup + filter, stop after hypotheses
python -m revelio.run.detect \
    --arvo revelio/assimp:latest \
    --pipeline scan_filter \
    --model claude-haiku-4-5-20251001 \
    --filter-model anthropic/claude-sonnet-4-6 \
    --target-file code/AssetLib/FBX/FBXParser.cpp \
    --max-workers 8

# Full pipeline: scan_filter → PoC generation → validation → report
python -m revelio.run.detect \
    --arvo revelio/assimp:latest \
    --pipeline scan_filter_detect \
    --model claude-haiku-4-5-20251001 \
    --filter-model anthropic/claude-sonnet-4-6 \
    --poc-model anthropic/claude-opus-4-6 \
    --target-file code/AssetLib/FBX/FBXParser.cpp
```

#### Standalone scan_and_filter (direct CLI, for local repos)

```bash
# Analyze a local source file
python -m revelio.run.scan_and_filter \
    -f /path/to/repo/src/parser.c \
    --repo /path/to/repo \
    -m claude-haiku-4-5-20251001 \
    --filter-model anthropic/claude-sonnet-4-6 \
    --docker-image ubuntu:22.04 \
    --workers 8

# With a LiteLLM proxy
python -m revelio.run.scan_and_filter \
    -f /path/to/repo/src/parser.c \
    --repo /path/to/repo \
    -m litellm_proxy/claude-haiku-4-5-20251001 \
    --base-url https://your-litellm-proxy \
    --api-key sk-... \
    --filter-model litellm_proxy/claude-sonnet-4-6 \
    --workers 8 --filter-workers 4
```

#### Resuming from saved hypotheses

The `scan_filter` pipeline saves hypotheses to `output/<run_id>/hypotheses.json`. You can skip the scan stage and go straight to PoC generation:

```bash
python -m revelio.run.detect \
    --arvo revelio/assimp:latest \
    --hypotheses-file output/<run_id>/hypotheses.json \
    --model anthropic/claude-opus-4-6
```

### Key Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--pipeline` | `detect` | Pipeline mode: `file`, `project`, `detect`, `scan_filter`, or `scan_filter_detect` |
| `--target-file`, `-t` | — | Target file path (required for `--pipeline=file`) |
| `--max-workers` | `4` | Parallel workers for hypothesis generation |
| `--top-n` | `10` | Number of top hypotheses to pursue |
| `--max-poc-attempts` | `3` | Max validation attempts per hypothesis (PoCBuilder's `validate` tool calls) |
| `--keep-container` | `false` | Keep Docker container after run (for debugging) |
| `--agents-config-dir` | built-in | Custom directory for per-agent YAML configs |
| `--filter-model` | Sonnet 4.6 | Model for scan_filter Stage 3 sub-agent verification |
| `--filter-workers` | `4` | Parallel workers for sub-agent filtering |
| `--poc-model` | same as `--model` | Model for PoC builder/reporter agents |
| `--max-functions` | `50` | Max functions to analyze per file in scan_filter |
| `--agent-step-limit` | `20` | Max steps per scan_filter sub-agent |
| `--agent-cost-limit` | `2.0` | Max cost (USD) per scan_filter sub-agent |
| `--base-url` | — | LiteLLM proxy base URL |
| `--api-key` | `MODEL_API_KEY` | API key for LLM calls |
| `--hypotheses-file` | — | Load pre-generated hypotheses, skip scan stage |

### Cost Reports

```bash
# Summarize direct API cost plus cache/uncached token-cost estimates
SILENT_STARTUP=1 python -m revelio.run.cost_report output/<run_id>

# Also write output/<run_id>/cost_report.json and cost_report.md
SILENT_STARTUP=1 python -m revelio.run.cost_report output/<run_id> --write
```

The report reads saved `trajectory.json` and `traces/*.json`. For agent
trajectories it can split cost into cached input, uncached input, and output
when Anthropic/LiteLLM usage fields are present. Some scan_filter Stage 1/2
traces currently only save aggregate `cost`/`calls`, so those stages are
included in direct API cost but cannot always be split into cached/uncached
tokens retroactively.

### Validating PoCs

Validate PoCs against ARVO `-fix` images (patched versions):

```bash
python -m revelio.run.validate_if_target_multiAgent \
    --run-dir output/<run_id> \
    --poc output/<run_id>/artifacts/deliverables/poc_H01
```

CLI shortcuts:
- `revelio-validate-single` — single-agent run validator
- `revelio-validate-multi` — multi-agent run validator

## Environment Variables

### Model Selection

| Variable | Description |
|----------|-------------|
| `MODEL_NAME` | Default model name, e.g. `anthropic/claude-opus-4-6`, `openai/gpt-5`, `gemini/gemini-2.5-pro`, `openrouter/google/gemini-2.5-pro`. Always include the provider prefix. Can be overridden with `--model`. |

### API Keys

| Variable | Description |
|----------|-------------|
| `MODEL_API_KEY` | Generic API key passed to litellm. Works for any provider. |
| `MODEL_API_KEYS` | Comma-separated pool of API keys for parallel workers (round-robin assignment). Useful when running multiple `FileHypothesisRunner` instances to avoid rate limits. |
| `OPENAI_API_KEY` | OpenAI API key (used automatically by litellm for `openai/*` models) |
| `ANTHROPIC_API_KEY` | Anthropic API key (used automatically by litellm for `anthropic/*` models) |
| `GEMINI_API_KEY` | Google Gemini API key (used automatically by litellm for `gemini/*` models) |
| `OPENROUTER_API_KEY` | OpenRouter API key (used when model name starts with `openrouter/`, e.g. `openrouter/google/gemini-2.5-pro`) |

> **Tip:** You only need the provider-specific key for your chosen model (e.g., `ANTHROPIC_API_KEY` for Claude, `OPENROUTER_API_KEY` for OpenRouter). `MODEL_API_KEY` is an alternative that works across providers via litellm.

### Model Behavior

Temperature and other model parameters are configured **per-agent in YAML configs** (`src/revelio/config/agents/`), not via environment variables:

| Agent | Temperature | Purpose |
|-------|-------------|---------|
| `file_hypothesis.yaml` | 0.4 | Balanced hypothesis generation |
| `poc_builder.yaml` | 1.0 | Creative PoC building + validation |
| `validator.yaml` | 0.0 | Strict crash validation (standalone use) |
| `reporter.yaml` | 0.2 | Consistent report writing |

Above temperatures work for GPT and Claude model series.
For Gemini-3 series there's a community report of using temprature=1.0.

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
- **`trajectory.json`** — full conversation history for all agents, keyed by agent name. Used by the TUI inspector and web trace viewer.
- **`handoffs/`** — structured JSON data passed between pipeline stages (hypotheses, PoC recipes, validation results, reports)
- **`deliverables/`** — the final artifacts: bug report, PoC input file, and PoC generator script (only present when a vulnerability is confirmed)

## Project Structure

```
revelio/
├── agents/          # Agent implementations (DefaultAgent)
├── archived/        # Archived files from prior iterations during developing
├── artifacts/       # Artifact store (typed, append-only, thread-safe)
├── config/          # YAML configs: default.yaml, agents/, arvo_targets.json
├── environments/    # Execution environments (Local, Docker, Singularity)
├── models/          # LLM interfaces (LiteLLM, Anthropic, OpenRouter, Portkey)
├── orchestrator/    # Multi-agent pipeline + parallel hypothesis orchestration + scan-filter
├── run/             # CLI entry points (detect, scan_and_filter, inspector, validators, hello_world)
├── tools/           # Agent tools (bash, finish, validate)
├── utils/           # Utility functions
└── website/         # Web-based trace viewer
```

## Check Agent Running Trajectories

### Textual TUI for browsing trajectory JSON files

```bash
# TUI trajectory inspector (vim-style keybindings)
python -m revelio.run.inspector output/<run_id>/trajectory.json

# Or browse an entire output directory
python -m revelio.run.inspector output/
```

### Web Trace Viewer

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
