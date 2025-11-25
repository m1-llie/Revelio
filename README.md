# vul-agent

A trustworthy and precise vulnerability detection AI agent that discovers software vulnerabilities and validates them through automated PoC testing.

## Overview

vul-agent is an AI-powered security tool that:
- 🔍 **Discovers vulnerabilities** through intelligent code analysis
- ✅ **Validates findings** by validating PoC
- 📊 **Generates reports** with detailed PoC

## Features

- **AI-Powered Analysis**: Uses large language models to understand code and identify security issues
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

# Memory safety analysis (requires Docker)
python -m vulagent.run.memory_analysis -p examples/bof -m openai/gpt-5-mini

# Use Inspector to check trajectories
python -m vulagent.run.inspector memory_analysis_traj.json

# Or use the CLI
vul-agent -t "Your vulnerability detection task"
```

## Project Structure

```
vulagent/
├── agents/          # Agent implementations (DefaultAgent)
├── environments/    # Execution environments (Local, Docker)
├── models/         # LLM interfaces (LiteLLM, Anthropic, etc.)
├── run/            # CLI entry points and run scripts
├── config/         # Configuration templates
└── utils/          # Utility functions
```
