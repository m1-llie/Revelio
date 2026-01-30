# Entry points / run scripts

## Work locally (i.e., without a sandbox)

* `hello_world.py` - Extremely simple example of how to use the `default.py` agent.

## Vulnerability Detection

* `detect.py` - Detect memory-safety vulnerabilities using Docker sandbox. Supports:
  - `--arvo <image>` - ARVO targets with pre-built fuzzing infrastructure
  - `--project <path>` - Custom local C/C++ projects

## Extras

* `inspector.py` - Browse agent conversation trajectories.
* `extra/config.py` - Manage the global config file.