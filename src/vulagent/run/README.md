# Entry points / run scripts

## Work locally (i.e., without a sandbox)

* `hello_world.py` - Extremely simple example of how to use the `default.py` agent.

## Vulnerability Detection

* `detect.py` - Detect memory-safety vulnerabilities using Docker sandbox. Supports:
  - `--arvo <image>` - ARVO targets with pre-built fuzzing infrastructure
  - `--project <path>` - Custom local C/C++ projects

* `validate.py` - Validate a PoC against both ARVO versions:
  - Pulls `-fix` image if not cached locally
  - Tests PoC on both `-vul` and `-fix` versions
  - Passes if: crashes on vul AND no crash on fix
  - Usage: `python -m vulagent.run.validate --run-dir output/arvo-xxx/`

* `clean_arvo.py` - Prepare ARVO images for zero-day detection:
  - Removes pre-existing PoCs, crashers, and seed corpus
  - Creates new image tagged with `-clean` suffix
  - No rebuild needed (harness binaries preserved)
  - Usage: `python -m vulagent.run.clean_arvo --image n132/arvo:14935-vul`

## Extras

* `inspector.py` - Browse agent conversation trajectories.
* `extra/config.py` - Manage the global config file.