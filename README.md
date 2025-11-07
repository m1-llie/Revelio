# vul-agent

A trustworthy and precise vulnerability detection AI agent that discovers software vulnerabilities and validates them through automated exploitation testing.

## Overview

vul-agent is an AI-powered security tool that:
- 🔍 **Discovers vulnerabilities** through intelligent code analysis
- ✅ **Validates findings** by testing exploitation
- 📊 **Generates reports** with detailed proof-of-concept

## Features

- **AI-Powered Analysis**: Uses large language models to understand code and identify security issues
- **Automated Testing**: Validates vulnerabilities through controlled exploitation
- **Multiple Environments**: Supports local execution and Docker containers for safe testing
- **Extensible Architecture**: Easy to add new detection strategies and validation methods

## Quick Start

### Installation

```bash
# Clone the repository
git clone <your-repo-url>
cd vul-agent

# Install dependencies
pip install -e .
```

### Basic Usage

```python
from vulagent.agents.default import DefaultAgent
from vulagent.environments.local import LocalEnvironment
from vulagent.models.litellm_model import LitellmModel

# Create agent
agent = DefaultAgent(
    model=LitellmModel(model_name="gpt-4"),
    env=LocalEnvironment(),
)

# Run vulnerability detection
exit_status, result = agent.run("Analyze this code for security vulnerabilities: ...")
```

### Command Line

```bash
# Run with hello_world example
python -m vulagent

# Memory safety analysis (requires Docker)
python -m vulagent.run.memory_analysis -p examples/bof -m openai/gpt-5-mini

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
