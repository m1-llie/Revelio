# Multi-agent prompt configs

Each YAML file defines the agent prompt, formatting rules, and model parameters for the multi-agent vulnerability detection workflow.

Files:
- `file_hypothesis.yaml` - per-file vulnerability hypothesis generation (used by `FileHypothesisRunner`)
- `poc_builder.yaml` - PoC building + validation for a hypothesis. Target-aware: when the orchestrator identifies a matching fuzz target, the agent is told which harness to use. Uses the `validate` tool which automatically tests PoCs against all available sanitizers.
- `validator.yaml` - standalone crash validation & evidence capture (available for direct use, but the main pipeline now uses the `validate` tool within PoCBuilder instead)
- `reporter.yaml` - final bug report

Note: The old monolithic `hypothesis.yaml` for HypothesisAgent in multi-agent structure v2 has been archived to `src/vulagent/archived/hypothesis_old.yaml`.
It is replaced by `file_hypothesis.yaml` which is run per-file in parallel by `HypothesisOrchestrator`.
