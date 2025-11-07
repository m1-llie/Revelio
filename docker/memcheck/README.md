# Memory Analysis Docker Image

Base image for running memory-safety analysis inside vul-agent.

## Build

```
docker build -t vulagent/memcheck:latest docker/memcheck
```

## Contents
- Ubuntu 22.04
- build-essential, clang, gdb, cmake, ninja
- Python 3 with pip, litellm (for parity with host tooling)
- Valgrind and common development utilities

The container is expected to run with `/workspace` mounted from the host. The
`DockerEnvironment` sleeps in the background while commands are executed via
`docker exec`.
