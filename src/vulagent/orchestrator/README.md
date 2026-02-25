# Orchestrator

This package implements the multi-agent pipeline used by `detect.py`.

Key files:
- `runner.py` - `MultiAgentOrchestrator` state machine and `AgentRunner`.
- `hypothesis.py` - `HypothesisOrchestrator`: parallel file-level scanning coordinator.
- `file_hypothesis.py` - `FileHypothesisRunner`: per-file hypothesis agent runner.
- `context.py` - Artifact-to-prompt context packet builder.
- `parsers.py` - Parsing of structured agent outputs (YAML/JSON).
- `specs.py` - Default agent specs and config wiring.
- `types.py` - Shared types (`AgentSpec`, `AgentRunResult`, `OrchestratorResult`).

The orchestrator reads global artifacts from the store and injects a compact,
role-specific context packet into each agent prompt to reduce information loss.

Pipeline stages:
1. **Hypothesis generation** - `HypothesisOrchestrator` enumerates source files,
   runs `FileHypothesisRunner` per file in parallel via `ThreadPoolExecutor`,
   then merges and ranks all hypotheses by confidence.
2. **PoC generation** - `PoCBuilderAgent` builds a PoC for each hypothesis.
3. **Validation** - `ValidatorAgent` runs the PoC and captures crash evidence.
4. **Reporting** - `ReporterAgent` writes a bug report for confirmed crashes.

Pipeline modes (controlled via `--pipeline` flag in `detect.py`):
- `file` - Single file hypothesis only (uses `FileHypothesisRunner` directly).
- `project` - Parallel hypotheses only (stops after stage 1).
- `detect` - Full pipeline (all four stages).
