# Multi-agent prompt configs

Each YAML file defines the agent prompt, formatting rules, and model parameters for the multi-agent vulnerability detection workflow.

Files:
- `reviewer.yaml` - repo review and reachability notes
- `hypothesis.yaml` - top-10 vulnerability hypotheses
- `poc_builder.yaml` - PoC generation for a hypothesis
- `validator.yaml` - crash validation & evidence capture
- `reporter.yaml` - final bug report
