# Entry points / run scripts

## Work locally (i.e., without a sandbox)

* `hello_world.py` - Extremely simple example of how to use the `default.py` agent.

## Vulnerability Detection

* `detect.py` - Detect memory-safety vulnerabilities using Docker sandbox. Supports:
  - `--arvo <image>` - ARVO targets with pre-built fuzzing infrastructure
  - `--project <path>` - Custom local C/C++ projects
  - `--pipeline <mode>` - Pipeline mode: `file` (single file hypothesis), `project` (parallel hypotheses only), `detect` (full pipeline, default), `scan_filter` (multi-pass scan + filter), `scan_filter_detect` (scan_filter then PoC + report)
  - `--target-file <path>` - Target file path relative to project root (required for `--pipeline file`)
  - `--max-workers <n>` - Number of parallel workers for hypothesis generation (default: 4)
  - `--agents-config-dir <path>` - Directory for per-agent prompt configs (default: config/agents)
  - `--top-n <n>` - Number of hypotheses to use from the hypothesis stage (default: 10)
  - `--max-poc-attempts <n>` - Max validate tool calls per hypothesis (default: 3)
  - `--filter-model` - Model for scan_filter Stage 3 sub-agent verification
  - `--poc-model` - Model for PoC builder/reporter agents
  - `--hypotheses-file` - Load pre-generated hypotheses, skip scan stage

* `scan_and_filter.py` - Standalone scan-and-filter CLI for local repos (without Docker-based PoC generation). Runs multi-pass LLM analysis, classification/dedup, and Docker sub-agent filtering on individual source files.

* `validate_if_target_singleAgent.py` - Validate a PoC against both ARVO versions:
  - Pulls `-fix` image if not cached locally
  - Tests PoC on both `-vul` and `-fix` versions
  - Passes if: crashes on vul AND no crash on fix
  - Usage: `python -m vulagent.run.validate_if_target_singleAgent --run-dir output/arvo-xxx/`

* `validate_if_target_multiAgent.py` - Validate a PoC from multi-agent runs:
  - Uses `manifest.json` to resolve the ARVO image (or `--arvo-image`)
  - Supports per-hypothesis PoCs (e.g., `hypothesis_H01/poc_H01`)
  - Usage:
    - `python -m vulagent.run.validate_if_target_multiAgent --run-dir output/arvo-xxx/ --poc output/arvo-xxx/hypothesis_H01/poc_H01`

* `clean_arvo.py` - Prepare ARVO images for zero-day detection:
  - Removes pre-existing PoCs, crashers, and seed corpus
  - Creates new image tagged with `-clean` suffix
  - No rebuild needed (harness binaries preserved)
  - Usage: `python -m vulagent.run.clean_arvo --image n132/arvo:14935-vul`

## Extras

* `inspector.py` - Browse agent conversation trajectories.
  - Supports aggregated multi-agent `trajectory.json` (use `n`/`p` to switch agents).
* `extra/config.py` - Manage the global config file.
