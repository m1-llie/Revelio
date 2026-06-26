# Software Vulnerability Analysis Docker Image

Base image for running software analysis (e.g., inspect memory safety issues) inside revelio.

## Build

```
docker build -t revelio/memcheck:latest docker/memcheck
```

## Contents
- Ubuntu 22.04
- build-essential, clang, gdb, cmake, ninja, meson
- Python 3 with pip, litellm (for parity with host tooling)
- zlib1g-dev for common C deps
- Valgrind and common development utilities

The container is expected to run with `/workspace` mounted from the host.
The `DockerEnvironment` sleeps in the background while commands are executed via `docker exec`.
