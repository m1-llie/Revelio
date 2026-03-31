# vul-agent

A trustworthy and precise vulnerability detection AI agent that discovers software vulnerabilities and validates them through automated PoC testing.

- **Discovers vulnerabilities** through code review
- **Validates findings** by building and running PoC inputs
- **Generates reports** with detailed vulnerability information and reproduction steps

## Architecture

### Pipeline Stages

1. **HypothesisOrchestrator** — enumerates source files, runs `FileHypothesisRunner` per file in parallel, merges and ranks hypotheses by confidence
2. **PoCBuilderAgent** — generates a deterministic PoC input and generator script for each hypothesis
3. **ValidatorAgent** — runs the PoC against the target and checks for sanitizer/crash output
4. **ReporterAgent** — writes a final bug report with vulnerability details and reproduction steps

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
                │                                   ├── PoCBuilderAgent × N  (pipeline=detect only)
                │                                   ├── ValidatorAgent × N   (pipeline=detect only)
                │                                   └── ReporterAgent × N    (pipeline=detect only)
                │
                └── pipeline=scan_filter|scan_filter_detect
                         ──► ScanFilterOrchestrator (per file)
                               ├── Stage 1: Multi-pass LLM analysis (tree-sitter + focused passes)
                               ├── Stage 2: LLM classification + dedup
                               ├── Stage 3: Docker sub-agent filtering
                               └── (scan_filter_detect only) ──► MultiAgentOrchestrator
                                     ├── PoCBuilderAgent × N
                                     ├── ValidatorAgent × N
                                     └── ReporterAgent × N
```

- **`--pipeline file`** — run hypothesis generation on a single file only
- **`--pipeline project`** — run parallel hypothesis generation on all source files, stop before PoC related steps
- **`--pipeline detect`** (default) — full pipeline: hypotheses → PoC validation → report
- **`--pipeline scan_filter`** — multi-pass scan → classify/dedup → Docker sub-agent filter, stop after hypotheses
- **`--pipeline scan_filter_detect`** — scan_filter → PoC generation → validation → report

Each `FileHypothesisRunner` wraps a `DefaultAgent` with `file_hypothesis.yaml` config.

The `scan_filter` pipeline uses three separate model tiers:
- **`--model`** — cheap/fast model for Stage 1-2 hypothesis generation (e.g., Haiku)
- **`--filter-model`** — mid-tier model for Stage 3 sub-agent verification (e.g., Sonnet)
- **`--poc-model`** — strongest model for PoC/validation/report (e.g., Opus, only in `scan_filter_detect`)

## Quick Start

### Installation

```bash
git clone <repo-url>
cd vul-agent
```

**conda env**

```bash
conda create -n vul-agent python=3.12 -y
conda activate vul-agent
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
```

Alternatively, run the interactive setup:

```bash
vul-agent config setup
```

### Hello World

Test the installation with a simple task (no Docker required):

```bash
vul-agent -t "List all files in the current directory and describe what they do"
```

## Building OSS-Fuzz Docker Images

To analyze OSS-Fuzz projects, you need to build the fuzzers with code sanitizers and package them into a Docker image with the `arvo` runner script.

### Step 1: Build fuzzers with OSS-Fuzz

```bash
# Clone oss-fuzz
git clone https://github.com/google/oss-fuzz.git ~/oss-fuzz
cd ~/oss-fuzz

# Build fuzzers for a project (uses address sanitizer by default)
python infra/helper.py build_fuzzers --sanitizer address <project_name>
# e.g. python infra/helper.py build_fuzzers --sanitizer address assimp

# Verify the build produced fuzzer binaries
ls build/out/<project_name>/
```

### Step 2: Package into a vulagent-ready container

The `scripts/create_ossfuzz_containers.sh` script automates packaging. It:
1. Starts a container from the OSS-Fuzz base image (`gcr.io/oss-fuzz/<project>`)
2. Copies the compiled fuzzer binaries into `/out/`
3. Installs the `arvo` script at `/usr/bin/arvo`
4. Commits the container as `vulagent/<project>:latest`

```bash
# Edit the script to add your projects, then run:
bash scripts/create_ossfuzz_containers.sh
```

Or do it manually for a single project:

```bash
PROJECT=assimp
OSS_FUZZ_DIR=~/oss-fuzz

# Start a container from the oss-fuzz base image
docker run -d --name setup-${PROJECT} gcr.io/oss-fuzz/${PROJECT}:latest sleep 3600

# Copy compiled fuzzers into /out/
docker exec setup-${PROJECT} mkdir -p /out
docker cp ${OSS_FUZZ_DIR}/build/out/${PROJECT}/. setup-${PROJECT}:/out/

# Copy the arvo script (handles ASAN env vars + fuzzer invocation)
docker cp scripts/arvo_ossfuzz setup-${PROJECT}:/usr/bin/arvo
docker exec setup-${PROJECT} chmod +x /usr/bin/arvo

# Verify fuzzers are available
docker exec setup-${PROJECT} arvo list

# Commit as a reusable image
docker commit setup-${PROJECT} vulagent/${PROJECT}:latest
docker rm -f setup-${PROJECT}
```

### The `arvo` script

The `arvo` script inside the container provides a standard interface for running fuzzers:

```bash
arvo list                    # List available fuzzer binaries in /out/
arvo run <fuzzer> /tmp/poc   # Run a specific fuzzer with a PoC input
arvo run <fuzzer>            # Run with /tmp/poc (default)
```

It sets the standard ASAN/MSAN/UBSAN environment variables so that sanitizer crashes are properly reported.

### Verifying the image

```bash
# List available fuzzers
docker run --rm vulagent/assimp:latest arvo list

# Test a PoC (mount it as /tmp/poc)
docker run --rm -v /path/to/poc:/tmp/poc:ro vulagent/assimp:latest \
    timeout 30 arvo run assimp_fuzzer
```

## Vul-agent for Vulnerability Detection

### ARVO Targets

[ARVO](https://github.com/n132/ARVO) provides pre-built Docker images with fuzzing infrastructure.

```bash
# Full pipeline (default): hypotheses → PoC validation → report
python -m vulagent.run.detect \
    --arvo n132/arvo:42470801-vul-clean \
    --model anthropic/claude-opus-4-6

# Parallel hypothesis generation only (no PoC/validation/report)
python -m vulagent.run.detect \
    --arvo n132/arvo:42470801-vul-clean \
    --model anthropic/claude-opus-4-6 \
    --pipeline project \
    --max-workers 8

# Single file hypothesis only
python -m vulagent.run.detect \
    --arvo n132/arvo:42470801-vul-clean \
    --model anthropic/claude-opus-4-6 \
    --pipeline file \
    --target-file coders/svg.c
```

> **Note:** `arvo:xxx-vul-clean` images are produced using `python -m vulagent.run.clean_arvo`
> to remove pre-existing PoCs, crashers, and seed corpus from ARVO-vul images.

### OSS-Fuzz Targets

For OSS-Fuzz Docker images built with the steps above:

```bash
# Full pipeline: scan → hypotheses → PoC → validate → report
python -m vulagent.run.detect \
    --arvo vulagent/assimp:latest \
    --model anthropic/claude-opus-4-6

# Scan a specific file
python -m vulagent.run.detect \
    --arvo vulagent/assimp:latest \
    --model anthropic/claude-opus-4-6 \
    --pipeline file \
    --target-file code/AssetLib/FBX/FBXBinaryTokenizer.cpp
```

### Custom Projects

Example: Single file hypothesis on a custom project

```bash
python -m vulagent.run.detect \
    --project ./my-project \
    --model anthropic/claude-opus-4-6 \
    --pipeline file \
    --target-file src/parser.c
```

Use `--docker-image` to specify a custom Docker base image (default: `vulagent/memcheck:latest`).

### Scan-and-Filter Pipeline

The `scan_filter` pipeline uses a more thorough multi-pass analysis: tree-sitter function parsing, multiple focused LLM passes, LLM-based classification/dedup, and Docker sub-agent verification. It can be run standalone or as the front-end to the full PoC generation pipeline.

#### Standalone scan_and_filter (via detect.py)

```bash
# Scan + classify + dedup + filter, stop after hypotheses
python -m vulagent.run.detect \
    --arvo vulagent/assimp:latest \
    --pipeline scan_filter \
    --model claude-haiku-4-5-20251001 \
    --filter-model anthropic/claude-sonnet-4-6 \
    --target-file code/AssetLib/FBX/FBXParser.cpp \
    --max-workers 8

# Full pipeline: scan_filter → PoC generation → validation → report
python -m vulagent.run.detect \
    --arvo vulagent/assimp:latest \
    --pipeline scan_filter_detect \
    --model claude-haiku-4-5-20251001 \
    --filter-model anthropic/claude-sonnet-4-6 \
    --poc-model anthropic/claude-opus-4-6 \
    --target-file code/AssetLib/FBX/FBXParser.cpp
```

#### Standalone scan_and_filter (direct CLI, for local repos)

```bash
# Analyze a local source file
python -m vulagent.run.scan_and_filter \
    -f /path/to/repo/src/parser.c \
    --repo /path/to/repo \
    -m claude-haiku-4-5-20251001 \
    --filter-model anthropic/claude-sonnet-4-6 \
    --docker-image ubuntu:22.04 \
    --workers 8

# With a LiteLLM proxy
python -m vulagent.run.scan_and_filter \
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
python -m vulagent.run.detect \
    --arvo vulagent/assimp:latest \
    --hypotheses-file output/<run_id>/hypotheses.json \
    --model anthropic/claude-opus-4-6
```

### Key Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--pipeline` | `detect` | Pipeline mode: `file`, `project`, `detect`, `scan_filter`, or `scan_filter_detect` |
| `--target-file`, `-t` | — | Target file path (required for `--pipeline=file`) |
| `--max-workers` | `4` | Parallel workers for hypothesis generation |
| `--top-n` | `5` | Number of top hypotheses to pursue |
| `--max-poc-attempts` | `2` | Max PoC build + validation attempts per hypothesis |
| `--keep-container` | `false` | Keep Docker container after run (for debugging) |
| `--agents-config-dir` | built-in | Custom directory for per-agent YAML configs |
| `--filter-model` | Sonnet 4.6 | Model for scan_filter Stage 3 sub-agent verification |
| `--filter-workers` | `4` | Parallel workers for sub-agent filtering |
| `--poc-model` | same as `--model` | Model for PoC/validator/reporter agents |
| `--max-functions` | `50` | Max functions to analyze per file in scan_filter |
| `--agent-step-limit` | `20` | Max steps per scan_filter sub-agent |
| `--agent-cost-limit` | `2.0` | Max cost (USD) per scan_filter sub-agent |
| `--base-url` | — | LiteLLM proxy base URL |
| `--api-key` | `MODEL_API_KEY` | API key for LLM calls |
| `--hypotheses-file` | — | Load pre-generated hypotheses, skip scan stage |

### Validating PoCs

Validate PoCs against ARVO `-fix` images (patched versions):

```bash
python -m vulagent.run.validate_if_target_multiAgent \
    --run-dir output/<run_id> \
    --poc output/<run_id>/artifacts/deliverables/poc_H01
```

CLI shortcuts:
- `vul-agent-validate-single` — single-agent run validator
- `vul-agent-validate-multi` — multi-agent run validator

## Environment Variables

### Model Selection

| Variable | Description |
|----------|-------------|
| `MODEL_NAME` | Default model name, e.g. `anthropic/claude-opus-4-6`, `openai/gpt-5`, `gemini/gemini-2.5-pro`. Always include the provider prefix. Can be overridden with `--model`. |

### API Keys

| Variable | Description |
|----------|-------------|
| `MODEL_API_KEY` | Generic API key passed to litellm. Works for any provider. |
| `MODEL_API_KEYS` | Comma-separated pool of API keys for parallel workers (round-robin assignment). Useful when running multiple `FileHypothesisRunner` instances to avoid rate limits. |
| `OPENAI_API_KEY` | OpenAI API key (used automatically by litellm for `openai/*` models) |
| `ANTHROPIC_API_KEY` | Anthropic API key (used automatically by litellm for `anthropic/*` models) |
| `GEMINI_API_KEY` | Google Gemini API key (used automatically by litellm for `gemini/*` models) |

> **Tip:** You only need the provider-specific key for your chosen model (e.g., `ANTHROPIC_API_KEY` for Claude). `MODEL_API_KEY` is an alternative that works across providers via litellm.

### Model Behavior

Temperature and other model parameters are configured **per-agent in YAML configs** (`src/vulagent/config/agents/`), not via environment variables:

| Agent | Temperature | Purpose |
|-------|-------------|---------|
| `file_hypothesis.yaml` | 0.4 | Balanced hypothesis generation |
| `poc_builder.yaml` | 0.2 | Deterministic PoC generation |
| `validator.yaml` | 0.0 | Strict crash validation |
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
    ├── handoffs/          # Inter-agent data (one JSON per stage + hypothesis + attempt)
    │   ├── hypotheses.json
    │   ├── poc_recipe_H01_attempt1.json
    │   ├── validation_H01_attempt1.json
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
vulagent/
├── agents/          # Agent implementations (DefaultAgent)
├── archived/        # Archived files from prior iterations during developing
├── artifacts/       # Artifact store (typed, append-only, thread-safe)
├── config/          # YAML configs: default.yaml, agents/, arvo_targets.json
├── environments/    # Execution environments (Local, Docker, Singularity)
├── models/          # LLM interfaces (LiteLLM, Anthropic, OpenRouter, Portkey)
├── orchestrator/    # Multi-agent pipeline + parallel hypothesis orchestration
├── run/             # CLI entry points (detect, inspector, validators, hello_world)
├── utils/           # Utility functions
└── website/         # Web-based trace viewer
```

## Check Agent Running Trajectories

### Textual TUI for browsing trajectory JSON files

```bash
# TUI trajectory inspector (vim-style keybindings)
python -m vulagent.run.inspector output/<run_id>/trajectory.json

# Or browse an entire output directory
python -m vulagent.run.inspector output/
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
