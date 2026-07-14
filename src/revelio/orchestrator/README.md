# Orchestrator

This package implements the multi-agent pipeline used by `detect.py`.

Key files:
- `runner.py` - `MultiAgentOrchestrator` state machine and `AgentRunner`.
- `hypothesis.py` - `HypothesisOrchestrator`: parallel file-level scanning coordinator.
- `file_hypothesis.py` - `FileHypothesisRunner`: per-file hypothesis agent runner.
- `scan_filter.py` - `ScanFilterOrchestrator`: multi-pass scan + classify/dedup + Docker sub-agent filtering.
- `scan_filter_stages.py` - hypothesis-proposal (extract functions / summarize file content / synthesize hypotheses), sanitizer-aware triage, deduplicate-root-causes, and independent-static-filtering implementations for the scan-filter pipeline (LLM calls, tree-sitter parsing, filter agent runner).
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
2. **Target matching** - For each hypothesis, `_discover_fuzz_targets()` runs
   `arvo targets <function>` (nm-based binary symbol lookup) to find which fuzz
   targets can reach the hypothesized function. Zero LLM cost.
3. **PoV building + validation** - For each matched target, `PoVBuilderAgent`
   builds a PoV and validates it via the `validate` tool. The validate tool
   automatically tests the PoV against all available sanitizers (asan, ubsan, msan).
   Stops on first confirmed crash.
4. **Reporting** - `ReporterAgent` writes a bug report for confirmed crashes.

Pipeline stages (`scan_filter_detect` — the only pipeline `detect.py` runs today; there is no
`--pipeline` flag). Two bands, matching the paper's Figure 3:

**Initial Hypothesis Proposal (proposal band)** — per file, high-recall expansion:
1. **Extract Functions** - tree-sitter function parsing. Deterministic, no LLM call.
2. **Summarize File Content** - a distinct LLM call producing a file summary; its
   conversation history seeds the passes below.
3. **Synthesize Hypotheses** - multiple concurrent single-shot LLM passes (whole-file,
   focused-assumption, per-function-batch — direct litellm calls, not agents), merged
   into the file's contribution to the Raw Hypothesis Pool.

**Hypothesis Triage and Filtering (refinement band)** — precision and ranking:
4. **In-scope Hypotheses** via sanitizer-aware triage - one LLM call per hypothesis:
   real vulnerability? ASAN/UBSAN/MSAN-triggerable?
5. **Merged Hypotheses** via deduplicate root causes - deterministic line/CWE-overlap
   prefilter + pairwise LLM judgement + union-find merge.
6. **Reachability-Annotated Hypotheses** via independent static filtering - split
   across two mechanisms: a deterministic `arvo targets` reachability annotation
   (advisory ranking signal only, never filters), then a real coding agent
   (`DefaultAgent` + unrestricted `bash` tool, full container/repo scope — not a
   single LLM call, not restricted to one file) that returns a VALID/INVALID verdict.
7. **Ranked Hypothesis Queue** via rank for PoV confirmation - deterministic sort by
   (reachable, severity, confidence), no LLM call.
8. Continues to `MultiAgentOrchestrator` for PoV building + validation + reporting.
