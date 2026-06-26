"""Validate tool for feeding a PoC to the ARVO harness and checking for crashes."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from revelio.run.crash_signals import (
    CRASH_SIGNATURES as CRASH_INDICATORS,
    CRASH_SIGNAL_RETURN_CODES as CRASH_RETURN_CODES,
    check_crash,
)

__all__ = ["CRASH_INDICATORS", "CRASH_RETURN_CODES", "check_crash", "make_validate_tool"]


def _truncate_output(output: str, max_lines: int = 200) -> str:
    lines = output.splitlines()
    if len(lines) <= max_lines:
        return output
    head = "\n".join(lines[: max_lines // 2])
    tail = "\n".join(lines[-(max_lines // 2) :])
    return f"{head}\n\n... ({len(lines) - max_lines} lines omitted) ...\n\n{tail}"


def _discover_sanitizers(env: Any) -> list[str]:
    """Detect available sanitizer directories under /out/.

    Returns sanitizer names (e.g. ["asan", "ubsan", "msan"]) for the
    multi-sanitizer layout, or an empty list for flat /out/ layouts
    (original ARVO images).
    """
    result = env.execute("ls -1d /out/asan /out/ubsan /out/msan 2>/dev/null || true")
    output = result.get("output", "").strip()
    if not output:
        return []
    return [line.rsplit("/", 1)[-1] for line in output.splitlines() if line.strip()]


def _format_result(sanitizer: str | None, crash: bool, returncode: int | None, output: str) -> str:
    header = f"[{sanitizer}] " if sanitizer else ""
    return (
        f"{header}crash_detected: {crash}\n"
        f"{header}returncode: {returncode}\n"
        f"{header}output:\n{_truncate_output(output)}"
    )


def make_validate_tool(env: Any) -> Callable:
    """Create a validate tool closure bound to the given environment."""

    sanitizers = _discover_sanitizers(env)

    def validate(poc_path: str) -> str:
        """Copy a PoC file to /tmp/poc and run arvo to check for a sanitizer crash.

        For multi-sanitizer images (OSS-Fuzz), the PoC is tested against
        every available sanitizer.  For single-sanitizer images (ARVO),
        it runs once with the default configuration.

        Args:
            poc_path: Absolute path to the PoC file inside the container.
        """
        env.execute(f"cp {poc_path} /tmp/poc")

        if not sanitizers:
            # Flat /out/ layout (original ARVO images) — single run
            result = env.execute("arvo 2>&1")
            output = result.get("output", "")
            returncode = result.get("returncode")
            return _format_result(None, check_crash(output, returncode), returncode, output)

        # Multi-sanitizer layout — test each sanitizer
        parts: list[str] = []
        any_crash = False
        for san in sanitizers:
            result = env.execute(f"SANITIZER={san} arvo 2>&1")
            output = result.get("output", "")
            returncode = result.get("returncode")
            crash = check_crash(output, returncode)
            if crash:
                any_crash = True
            parts.append(_format_result(san, crash, returncode, output))

        summary = f"crash_detected: {any_crash}\nsanitizers_tested: {', '.join(sanitizers)}\n\n"
        return summary + "\n---\n".join(parts)

    return validate
