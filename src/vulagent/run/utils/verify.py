"""Verification helpers for validating agent-produced reproduction commands."""

from __future__ import annotations

from dataclasses import dataclass, asdict
from typing import Iterable, Sequence

from vulagent import Environment

DEFAULT_CRASH_SIGNATURES: Sequence[str] = (
    "AddressSanitizer",
    "heap-buffer-overflow",
    "stack-buffer-overflow",
    "use-after-free",
    "Segmentation fault",
    "core dumped",
    "SIGSEGV",
)


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

    Parameters
    ----------
    env:
        Execution environment (Docker, local, etc.). Must expose ``execute``.
    command:
        Shell command to run (typically the agent-proposed reproduction).
    cwd:
        Working directory inside the environment (default: inherited from env).
    crash_signatures:
        Optional iterable of strings to search for in stdout. The default covers
        common sanitizer / crash indicators. Matching any signature counts as a
        crash even if the return code is zero (some sanitizers exit 1, some 77).
    timeout:
        Optional execution timeout passed to the environment.

    Returns
    -------
    VerificationResult
        Structured information about the run, including whether a crash was
        detected. This structure can be serialized into the trajectory metadata.
    """

    crash_patterns = list(crash_signatures or DEFAULT_CRASH_SIGNATURES)
    result = env.execute(command, cwd=cwd, timeout=timeout)
    output: str = result.get("output", "") or ""
    returncode: int = int(result.get("returncode", 0))

    indicators: list[str] = []
    if returncode != 0:
        indicators.append(f"non-zero return code ({returncode})")
    lowered = output.lower()
    for pattern in crash_patterns:
        if pattern.lower() in lowered:
            indicators.append(f"pattern: {pattern}")

    crash_detected = bool(indicators)

    return VerificationResult(
        command=command,
        cwd=cwd,
        returncode=returncode,
        output=output,
        crash_detected=crash_detected,
        indicators=indicators,
    )
