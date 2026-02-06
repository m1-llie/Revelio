# Entry points / run scripts

## Work locally (i.e., without a sandbox)

* `hello_world.py` - Extremely simple example of how to use the `default.py` agent.

## Vulnerability Detection

* `detect.py` - Detect memory-safety vulnerabilities using Docker sandbox. Supports:
  - `--arvo <image>` - ARVO targets with pre-built fuzzing infrastructure
  - `--project <path>` - Custom local C/C++ projects
  - `--multi-agent/--single-agent` - Use multi-agent pipeline (default) or legacy single-agent
  - `--agents-config-dir <path>` - Directory for per-agent prompt configs (default: config/agents)
  - `--max-poc-attempts <n>` - Max PoC attempts per hypothesis in multi-agent mode

* `validate.py` - Validate a PoC against both ARVO versions:
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
