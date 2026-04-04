# Assimp Collada Empty Attribute Assertion Failure

## Vulnerability

- **CWE**: CWE-617 (Reachable Assertion) / CWE-20 (Improper Input Validation)
- **Type**: Assertion failure (SIGABRT)
- **Severity**: Medium (DoS)
- **Component**: Assimp (Open Asset Import Library)
- **File**: Collada loader (multiple locations)
- **Crash**: `raise()` -> `abort()` triggered by assertion

## Description

A COLLADA file with empty `id=""` and `url=""` attributes on geometry, material, effect, and image elements triggers an assertion failure (SIGABRT) in Assimp's Collada loader. The parser assumes these attributes contain non-empty strings and performs operations such as `url[0]` (accessing the first character) and `id.size()-1` (unsigned underflow) without checking for empty input.

## Affected Versions

Tested on the Assimp version in the `vulagent/assimp:latest` ARVO image.

## Reproduction

```bash
python3 gen_poc.py
./reproduce.sh
```

## Root Cause

Multiple locations in the Collada loader access string attributes without validating they are non-empty. When `id=""`, the expression `id.size()-1` underflows (since `size_t` is unsigned), and `url[0]` reads from an empty string. The fix is to validate that required attributes are non-empty before use.
