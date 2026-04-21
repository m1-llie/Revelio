"""Verification helpers for validating agent-produced reproduction commands."""

from __future__ import annotations

from dataclasses import dataclass, asdict
from typing import Iterable, Sequence

from vulagent import Environment
from vulagent.run.crash_signals import (
    CRASH_SIGNATURES,
    check_crash,
    collect_indicators,
)

# Exposed for backwards compatibility with callers/tests that imported the
# old constant name. The canonical signatures live in crash_signals.
DEFAULT_CRASH_SIGNATURES: Sequence[str] = tuple(sorted(CRASH_SIGNATURES))


@dataclass
class VerificationResult:
    command: str
    cwd: str
    returncode: int
    output: str
    crash_detected: bool
    indicators: list[str]

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def run_verification(
    env: Environment,
    command: str,
    *,
    cwd: str = "",
    crash_signatures: Iterable[str] | None = None,
    timeout: int | None = None,
) -> VerificationResult:
    """Execute *command* inside *env* and determine whether it crashed.

    A crash is recorded only when the output contains a sanitizer / libFuzzer
    banner (see ``vulagent.run.crash_signals.CRASH_SIGNATURES``) or the
    process is killed by a signal (return code >= 128 or one of the common
    explicit signal codes). A bare non-zero return code is intentionally
    *not* sufficient, because many language runtimes (V8/d8, Node, wasm)
    exit with code 1 on ordinary syntax/compile/runtime errors that are
    unrelated to memory safety.

    Parameters
    ----------
    env:
        Execution environment (Docker, local, etc.). Must expose ``execute``.
    command:
        Shell command to run (typically the agent-proposed reproduction).
    cwd:
        Working directory inside the environment.
    crash_signatures:
        Optional override for the crash-signature set. Defaults to the
        canonical ASan/MSan/UBSan/libFuzzer set.
    timeout:
        Optional execution timeout passed to the environment.
    """

    result = env.execute(command, cwd=cwd, timeout=timeout)
    output: str = result.get("output", "") or ""
    returncode: int = int(result.get("returncode", 0))

    crash_detected = check_crash(output, returncode, signatures=crash_signatures)
    indicators = collect_indicators(output, returncode, signatures=crash_signatures)

    return VerificationResult(
        command=command,
        cwd=cwd,
        returncode=returncode,
        output=output,
        crash_detected=crash_detected,
        indicators=indicators,
    )
