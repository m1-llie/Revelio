# Orchestrator

This package implements the multi-agent pipeline used by `detect.py`.

Key files:
- `runner.py` - `MultiAgentOrchestrator` state machine and `AgentRunner`.
- `hypothesis.py` - `HypothesisOrchestrator`: parallel file-level scanning coordinator.
- `file_hypothesis.py` - `FileHypothesisRunner`: per-file hypothesis agent runner.
- `scan_filter.py` - `ScanFilterOrchestrator`: multi-pass scan + classify/dedup + Docker sub-agent filtering.
- `scan_filter_stages.py` - Stage 1/2/3 implementations for the scan-filter pipeline (LLM calls, tree-sitter parsing, filter agent runner).
- `context.py` - Artifact-to-prompt context packet builder.
- `parsers.py` - Parsing of structured agent outputs (YAML/JSON).
- `specs.py` - Default agent specs and config wiring.
- `types.py` - Shared types (`AgentSpec`, `AgentRunResult`, `OrchestratorResult`).

The orchestrator reads global artifacts from the store and injects a compact,
role-specific context packet into each agent prompt to reduce information loss.

Pipeline stages (detect mode):
1. **Hypothesis generation** - `HypothesisOrchestrator` enumerates source files,
   runs `FileHypothesisRunner` per file in parallel via `ThreadPoolExecutor`,
   then merges and ranks all hypotheses by confidence.
2. **PoC building + validation** - `PoCBuilderAgent` builds a PoC for each hypothesis
   and validates it against the harness via the `validate` tool (iterating up to
   `max_poc_attempts` times).
3. **Reporting** - `ReporterAgent` writes a bug report for confirmed crashes.

Pipeline stages (scan_filter / scan_filter_detect):
1. **Stage 1: Multi-pass hypothesis generation** - Tree-sitter function parsing,
   multiple focused LLM passes (direct litellm calls, not agents).
2. **Stage 2: Classification + dedup** - LLM-based classification (real vuln? ASAN-triggerable?)
   and pairwise deduplication with union-find.
3. **Stage 3: Docker sub-agent filtering** - `DefaultAgent` in shared container
   inspects code statically, returns VALID/INVALID verdict.
4. **(scan_filter_detect only)** - Continues to `MultiAgentOrchestrator` for PoC + report stages.

Pipeline modes (controlled via `--pipeline` flag in `detect.py`):
- `file` - Single file hypothesis only (uses `FileHypothesisRunner` directly).
- `project` - Parallel hypotheses only (stops after stage 1).
- `detect` - Full pipeline (hypothesis + PoC + report).
- `scan_filter` - Multi-pass scan + classify/dedup + filter (stops after hypotheses).
- `scan_filter_detect` - scan_filter then PoC building + validation + report.
