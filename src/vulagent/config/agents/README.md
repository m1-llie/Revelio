# Multi-agent prompt configs

Each YAML file defines the agent prompt, formatting rules, and model parameters for the multi-agent vulnerability detection workflow.

Files:
- `hypothesis.yaml` - combined repo review + top-N hypotheses (no PoC/validation)
- `poc_builder.yaml` - PoC generation for a hypothesis
- `validator.yaml` - crash validation & evidence capture
- `reporter.yaml` - final bug report
