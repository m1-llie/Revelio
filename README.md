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

```
detect.py  --pipeline [file | project | detect]
           --arvo / --project
           --target-file  (required for --pipeline=file)
                │
                ├── pipeline=file ──► FileHypothesisRunner (single file, direct)
                │
                └── pipeline=project|detect ──► MultiAgentOrchestrator
                                                    ├── HypothesisOrchestrator
                                                    │     └── FileHypothesisRunner × N (parallel)
                                                    ├── PoCBuilderAgent × N  (pipeline=detect only)
                                                    ├── ValidatorAgent × N   (pipeline=detect only)
                                                    └── ReporterAgent × N    (pipeline=detect only)
```

- **`--pipeline file`** — run hypothesis generation on a single file only
- **`--pipeline project`** — run parallel hypothesis generation on all source files, stop before PoC related steps
- **`--pipeline detect`** (default) — full pipeline: hypotheses → PoC validation → report

Each `FileHypothesisRunner` wraps a `DefaultAgent` with `file_hypothesis.yaml` config.

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

### Custom Projects

```bash
python -m vulagent.run.detect \
    --project ./my-project \
    --model anthropic/claude-opus-4-6
```

Use `--docker-image` to specify a custom Docker base image (default: `vulagent/memcheck:latest`).

### Key Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--pipeline` | `detect` | Pipeline mode: `file`, `project`, or `detect` |
| `--target-file`, `-t` | — | Target file path (required for `--pipeline=file`) |
| `--max-workers` | `4` | Parallel workers for hypothesis generation |
| `--top-n` | `5` | Number of top hypotheses to pursue |
| `--max-poc-attempts` | `2` | Max PoC build + validation attempts per hypothesis |
| `--keep-container` | `false` | Keep Docker container after run (for debugging) |
| `--agents-config-dir` | built-in | Custom directory for per-agent YAML configs |

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
