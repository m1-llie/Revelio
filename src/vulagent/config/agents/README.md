# Multi-agent prompt configs

Each YAML file defines the agent prompt, formatting rules, and model parameters for the multi-agent vulnerability detection workflow.

Files:
- `file_hypothesis.yaml` - per-file vulnerability hypothesis generation (used by `FileHypothesisRunner`)
- `poc_builder.yaml` - PoC generation for a hypothesis
- `validator.yaml` - crash validation & evidence capture
- `reporter.yaml` - final bug report

Note: The old monolithic `hypothesis.yaml` for HypothesisAgent in multi-agent structure v2 has been archived to `src/vulagent/archived/hypothesis_old.yaml`.
It is replaced by `file_hypothesis.yaml` which is run per-file in parallel by `HypothesisOrchestrator`.
