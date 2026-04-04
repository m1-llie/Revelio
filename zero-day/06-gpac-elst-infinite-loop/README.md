# GPAC Edit List (elst) Infinite Processing Loop

## Vulnerability

- **CWE**: CWE-835 (Loop with Unreachable Exit Condition) / CWE-400 (Uncontrolled Resource Consumption)
- **Type**: Denial of Service (infinite loop)
- **Severity**: Medium (DoS, 100% CPU)
- **Component**: GPAC multimedia framework
- **File**: Media sample processing / edit list mapping code
- **Trigger**: `fuzz_probe_analyze` fuzzer / `gf_isom_open_file` + probe/analyze path

## Description

A crafted MP4 file (~767 bytes) with an `elst` (Edit List) box containing `media_time = 0x7FFFFFFFFFFFFFFF` (INT64_MAX) causes GPAC's sample processing to enter an infinite loop. When probing/analyzing the file, GPAC emits hundreds of thousands of identical packets per second with no termination condition.

In testing, the PoC produced 619,987 output lines in 10 seconds before being killed by `timeout`. The process consumes 100% CPU and never terminates on its own.

## Affected Versions

Tested against the GPAC version in the `vulagent/gpac:latest` ARVO image.

## Reproduction

```bash
python3 gen_poc.py
./reproduce.sh
```

The reproduce script runs the PoC with a 10-second timeout and counts emitted packets to confirm the infinite loop.

## Root Cause

The edit list time mapping code uses `media_time` to compute sample offsets. When `media_time = INT64_MAX`, the arithmetic overflows or produces a condition where the sample iterator never advances past the current position, causing an infinite loop of packet emission. The fix is to validate `media_time` values in the `elst` box against reasonable bounds before use.
