"""Canonical crash detection for sanitizer-based validation.

Memory-safety validation across diverse targets (native C/C++ harnesses,
V8/JavaScript fuzzers, WebAssembly runtimes, etc.) must only report a
"crash" when evidence points to a genuine memory-safety / UB issue. A bare
non-zero exit code is *not* sufficient: many language runtimes (V8/d8,
Node.js, wasm) exit with code 1 on ordinary syntax, compile, or uncaught
runtime errors that are unrelated to memory safety.

Crash detection here is driven by two strict signals:

1. **Sanitizer / libFuzzer banner strings** appearing in the output. These
   cover AddressSanitizer, MemorySanitizer, UndefinedBehaviorSanitizer,
   and the libFuzzer/OSS-Fuzz crash wrappers used by most fuzzing
   harnesses (including V8's fuzzer builds). Leak detection is out of
   scope here: memory leaks are correctness/resource issues, not memory
   safety violations, and leak detection is explicitly disabled in the
   ARVO/OSS-Fuzz validator configs (``ASAN_OPTIONS: detect_leaks=0``).
2. **Signal-termination return codes** (>= 128, i.e. 128 + signal number,
   or common explicit codes such as 134/SIGABRT, 136/SIGFPE, 137/SIGKILL,
   139/SIGSEGV). These indicate the process was killed by the OS, which
   is always a genuine crash regardless of the language runtime.

A bare exit code of 1 is intentionally *not* a crash signal: it is the
default "something went wrong" code for JS/WASM runtimes and build tools.
When a sanitizer genuinely fires it additionally prints a banner, so the
string match catches it reliably.
"""

from __future__ import annotations

from collections.abc import Iterable


# Substring matches are performed case-insensitively against the full
# program output. Each entry is a canonical signature a sanitizer or
# fuzzing harness emits when a real crash occurs.
CRASH_SIGNATURES: frozenset[str] = frozenset({
    # AddressSanitizer
    "addresssanitizer",
    "heap-buffer-overflow",
    "stack-buffer-overflow",
    "global-buffer-overflow",
    "heap-use-after-free",
    "stack-use-after-free",
    "use-after-poison",
    "double-free",
    "alloc-dealloc-mismatch",
    "stack-overflow",
    "dynamic-stack-buffer-overflow",
    "container-overflow",
    # MemorySanitizer
    "memorysanitizer",
    "use-of-uninitialized-value",
    # UndefinedBehaviorSanitizer
    "undefinedbehaviorsanitizer",
    "runtime error:",  # UBSAN format, always "runtime error: <kind>"
    # Generic / libFuzzer / OSS-Fuzz wrappers.
    # These are anchored on punctuation / fixed prefixes to avoid
    # false-positive substring matches inside file paths or log lines
    # (e.g. "/out/ubsan/fuzzer", "installing SIGSEGV handler",
    # "libFuzzer: aborting after 1000 runs"). Bare signal tokens are
    # intentionally omitted: real signal-induced crashes are caught by
    # the signal-return-code path (>=128), and ASAN/libFuzzer banners
    # always co-occur with "==error:" / "deadly signal" / "ABORTING".
    "==error:",
    "deadly signal",
    "libfuzzer: out-of-memory",
    "==aborting",  # libFuzzer end-of-crash banner, always "==NNN==ABORTING"
    # Explicit crash assertions (substring-anchored with punctuation
    # where possible so they do not fire on arbitrary log text).
    "assertion failed",
    "check failed:",
})

# Explicit return codes that indicate signal-based process death.
# (Signal-death is always crash-qualifying.) We also accept any code
# >= 128 as signal-induced; this set documents the common ones.
CRASH_SIGNAL_RETURN_CODES: frozenset[int] = frozenset({
    134,  # SIGABRT
    136,  # SIGFPE
    137,  # SIGKILL (often from OOM killer / timeout wrappers)
    138,  # SIGBUS
    139,  # SIGSEGV
})


def is_signal_returncode(returncode: int | None) -> bool:
    """Return True iff *returncode* indicates signal-induced process death."""
    if returncode is None:
        return False
    if returncode >= 128:
        return True
    return returncode in CRASH_SIGNAL_RETURN_CODES


def find_matched_signatures(
    output: str,
    signatures: Iterable[str] | None = None,
) -> list[str]:
    """Return the subset of *signatures* that appear (case-insensitively) in *output*."""
    if not output:
        return []
    haystack = output.lower()
    pool = signatures if signatures is not None else CRASH_SIGNATURES
    return [sig for sig in pool if sig.lower() in haystack]


def check_crash(
    output: str | None,
    returncode: int | None,
    *,
    signatures: Iterable[str] | None = None,
) -> bool:
    """Return True iff the run exhibits a genuine sanitizer / signal crash.

    A non-zero return code *alone* is intentionally insufficient: many
    language runtimes (V8/d8, Node, wasm) exit with code 1 on routine
    non-crash errors (syntax, compile, uncaught exception, wasm trap).
    """
    if output and find_matched_signatures(output, signatures):
        return True
    return is_signal_returncode(returncode)


def collect_indicators(
    output: str | None,
    returncode: int | None,
    *,
    signatures: Iterable[str] | None = None,
) -> list[str]:
    """Return a human-readable list of indicators that contributed to the decision.

    This is useful for populating ``ValidationResult.indicators`` and
    similar diagnostic fields. Non-zero return codes that are *not*
    signal-induced are surfaced as non-crash diagnostics rather than
    crash evidence.
    """
    indicators: list[str] = []
    for sig in find_matched_signatures(output or "", signatures):
        indicators.append(f"pattern: {sig}")
    if returncode is not None:
        if is_signal_returncode(returncode):
            indicators.append(f"signal return code ({returncode})")
        elif returncode != 0:
            indicators.append(f"non-zero return code ({returncode}) [non-crash]")
    return indicators


__all__ = [
    "CRASH_SIGNATURES",
    "CRASH_SIGNAL_RETURN_CODES",
    "is_signal_returncode",
    "find_matched_signatures",
    "check_crash",
    "collect_indicators",
]
