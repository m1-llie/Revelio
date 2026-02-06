# vul-agent

A trustworthy and precise vulnerability detection AI agent that discovers software vulnerabilities and validates them through automated PoC testing.

## Overview

vul-agent is an AI-powered security tool that:
- 🔍 **Discovers vulnerabilities** through intelligent code analysis
- ✅ **Validates findings** by validating PoC
- 📊 **Generates reports** with detailed PoC

## Features

- **AI-Powered Analysis**: Uses large language models to understand code and identify security issues
- **Multi-Agent Pipeline**: Reviewer → Hypotheses → PoC → Validation → Report
- **Automated Testing**: Validates vulnerabilities through controlled PoC
- **Multiple Environments**: Supports local execution and Docker containers for safe testing
- **Extensible Architecture**: Easy to add new detection strategies and validation methods

## Quick Start

### Installation

```bash
# Clone the repository
git clone <repo-url>
cd vul-agent

# Install dependencies
pip install -e .
```

### Command Line

```bash
# Run with hello_world example
python -m vulagent

# Vulnerability detection with ARVO targets (pre-built Docker images)
python -m vulagent.run.detect --arvo n132/arvo:42470801-vul -m anthropic/claude-opus-4-6

# Vulnerability detection with custom projects (requires Docker)
python -m vulagent.run.detect --project examples/bof -m anthropic/claude-opus-4-6

# Use legacy single-agent mode (optional)
python -m vulagent.run.detect --arvo n132/arvo:42470801-vul --single-agent -m anthropic/claude-opus-4-6

# Use Inspector to check trajectories
python -m vulagent.run.inspector output/arvo-42470801-vul_*/trajectory.json

# Or use the CLI
vul-agent -t "Your vulnerability detection task"
```

### Outputs

Each run writes to `output/<run_id>/`:
- `trajectory.json` (aggregated multi-agent trajectory)
- `artifacts/trajectories/` (per-agent trajectories)
- `artifacts/logs/run.log`
- `poc`, `result_script.py`, `final_report.md` (if produced)

## Project Structure

```
vulagent/
├── agents/          # Agent implementations (DefaultAgent)
├── artifacts/       # Artifact store (typed, append-only) - see src/vulagent/artifacts/README.md
├── environments/    # Execution environments (Local, Docker)
├── models/         # LLM interfaces (LiteLLM, Anthropic, etc.)
├── orchestrator/    # Multi-agent pipeline + context injection - see src/vulagent/orchestrator/README.md
├── run/            # CLI entry points and run scripts
├── config/         # Configuration templates
└── utils/          # Utility functions
```
