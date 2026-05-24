"""Launch and execute commands inside a Docker container, handling env var forwarding and cleanup."""

import logging
import os
import shlex
import subprocess
import uuid
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class DockerEnvironmentConfig:
    image: str
    cwd: str = "/"
    """Working directory in which to execute commands."""
    env: dict[str, str] = field(default_factory=dict)
    """Environment variables to set in the container."""
    forward_env: list[str] = field(default_factory=list)
    """Environment variables to forward to the container.
    Variables are only forwarded if they are set in the host environment.
    In case of conflict with `env`, the `env` variables take precedence.
    """
    timeout: int = 30
    """Timeout for executing commands in the container."""
    executable: str = os.getenv("DOCKER_EXECUTABLE", "docker")
    """Path to the docker/container executable."""
    run_args: list[str] = field(default_factory=lambda: ["--rm"])
    """Additional arguments to pass to the docker/container executable.
    Default is ["--rm"], which removes the container after it exits.
    """
    container_timeout: str = "24h"
    """Max duration to keep container running. Uses the same format as the sleep command."""
    pull_timeout: int = 120
    """Timeout in seconds for pulling images."""
    post_start_commands: list[str] = field(default_factory=list)
    """Commands to run inside the container immediately after it starts (e.g. cleanup)."""
    sanitizer_compatible: bool = True
    """If True, relax Docker's default seccomp/cap filters so code sanitizers
    (MSan, ASan, UBSan) can initialize inside the container.

    Docker's default seccomp profile blocks ``personality()``. MSan calls
    ``personality(ADDR_NO_RANDOMIZE)`` during startup to disable ASLR for its
    shadow memory layout; when the syscall is blocked MSan aborts before the
    harness runs, which our crash detector (SIGABRT + "MemorySanitizer" banner)
    would otherwise misclassify as a real memory-safety crash.

    Concretely this adds to ``docker run``:
      - ``--security-opt seccomp=unconfined`` (unblocks ``personality()``)
      - ``--cap-add SYS_PTRACE`` (needed by ASan/LSan stack symbolizers)
    """


class DockerEnvironment:
    def __init__(self, *, config_class: type = DockerEnvironmentConfig, logger: logging.Logger | None = None, **kwargs):
        """This class executes bash commands in a Docker container using direct docker commands.
        See `DockerEnvironmentConfig` for keyword arguments.
        """
        self.logger = logger or logging.getLogger("vulagent.environment")
        self.container_id: str | None = None
        self.config = config_class(**kwargs)
        self._start_container()

    def get_template_vars(self) -> dict[str, Any]:
        return asdict(self.config)

    def _start_container(self):
        """Start the Docker container and return the container ID."""
        container_name = f"vulagent-{uuid.uuid4().hex[:8]}"
        sanitizer_args: list[str] = []
        if self.config.sanitizer_compatible:
            # See DockerEnvironmentConfig.sanitizer_compatible for rationale.
            # Only injected if the caller hasn't already specified equivalents,
            # so explicit user config always wins.
            user_args = self.config.run_args
            if not any("seccomp" in a for a in user_args):
                sanitizer_args.extend(["--security-opt", "seccomp=unconfined"])
            if "--cap-add" not in user_args:
                sanitizer_args.extend(["--cap-add", "SYS_PTRACE"])
        cmd = [
            self.config.executable,
            "run",
            "-d",
            "--name",
            container_name,
            "-w",
            self.config.cwd,
            *sanitizer_args,
            *self.config.run_args,
            self.config.image,
            "sleep",
            self.config.container_timeout,
        ]
        self.logger.debug(f"Starting container with command: {shlex.join(cmd)}")
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=self.config.pull_timeout,  # docker pull might take a while
            check=True,
        )
        self.logger.info(f"Started container {container_name} with ID {result.stdout.strip()}")
        self.container_id = result.stdout.strip()
        self._run_post_start_commands()

    def _run_post_start_commands(self):
        """Run configured post-start commands inside the container."""
        if not self.config.post_start_commands:
            return
        self.logger.info("Running post-start cleanup commands...")
        for command in self.config.post_start_commands:
            self.logger.debug(f"Post-start: {command}")
            result = subprocess.run(
                [self.config.executable, "exec", self.container_id, "bash", "-c", command],
                capture_output=True,
                text=True,
                timeout=self.config.timeout,
            )
            if result.returncode != 0:
                self.logger.warning(f"Post-start command failed (rc={result.returncode}): {command}")

    def execute(self, command: str, cwd: str = "", *, timeout: int | None = None) -> dict[str, Any]:
        """Execute a command in the Docker container and return the result as a dict."""
        cwd = cwd or self.config.cwd
        assert self.container_id, "Container not started"

        cmd = [self.config.executable, "exec", "-w", cwd]
        for key in self.config.forward_env:
            if (value := os.getenv(key)) is not None:
                cmd.extend(["-e", f"{key}={value}"])
        for key, value in self.config.env.items():
            cmd.extend(["-e", f"{key}={value}"])
        # Suppress "mesg: ttyname failed" from login shell in non-TTY environment
        wrapped_command = f"mesg n 2>/dev/null || true; {command}"
        cmd.extend([self.container_id, "bash", "-lc", wrapped_command])

        result = subprocess.run(
            cmd,
            text=True,
            timeout=timeout or self.config.timeout,
            encoding="utf-8",
            errors="replace",
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
        return {"output": result.stdout, "returncode": result.returncode, "exception_info": None}

    def cleanup(self):
        """Stop and remove the Docker container."""
        if getattr(self, "container_id", None) is not None:  # if init fails early, container_id might not be set
            cmd = f"(timeout 60 {self.config.executable} stop {self.container_id} || {self.config.executable} rm -f {self.container_id}) >/dev/null 2>&1 &"
            subprocess.Popen(cmd, shell=True)

    def __del__(self):
        """Cleanup container when object is destroyed."""
        self.cleanup()

    def copy_to(self, source: str | Path, destination: str | Path) -> None:
        """Copy a file from the host to the container."""
        assert self.container_id, "Container not started"
        src = Path(source)
        if not src.exists():
            raise FileNotFoundError(str(src))
        cmd = [
            self.config.executable,
            "cp",
            str(src),
            f"{self.container_id}:{destination}",
        ]
        result = subprocess.run(cmd, text=True, capture_output=True)
        if result.returncode != 0:
            message = result.stderr.strip() or result.stdout.strip()
            raise RuntimeError(message or "docker cp failed")

    def copy_from(self, source: str | Path, destination: str | Path) -> Path:
        """Copy a file from the container to the host and return the destination path."""
        assert self.container_id, "Container not started"
        src = str(source)
        dest = Path(destination)
        dest.parent.mkdir(parents=True, exist_ok=True)
        cmd = [
            self.config.executable,
            "cp",
            f"{self.container_id}:{src}",
            str(dest),
        ]
        result = subprocess.run(cmd, text=True, capture_output=True)
        if result.returncode != 0:
            message = result.stderr.strip() or result.stdout.strip()
            if "No such file" in message:
                raise FileNotFoundError(src)
            raise RuntimeError(message or "docker cp failed")
        return dest
