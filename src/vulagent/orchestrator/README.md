# Orchestrator

This package implements the multi-agent pipeline used by `detect.py`.

Key files:
- `runner.py` - Orchestrator state machine and agent runner.
- `context.py` - Artifact-to-prompt context packet builder.
- `parsers.py` - Parsing of structured agent outputs (YAML/JSON).
- `specs.py` - Default agent specs and config wiring.

The orchestrator reads global artifacts from the store and injects a compact,
role-specific context packet into each agent prompt to reduce information loss.
