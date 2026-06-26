# Assimp FBX Binary Tokenizer Stack Overflow

## Vulnerability

- **CWE**: CWE-674 (Uncontrolled Recursion)
- **Type**: Stack-based buffer overflow via uncontrolled recursion
- **Severity**: Medium (DoS / potential code execution)
- **Component**: Assimp (Open Asset Import Library)
- **File**: `code/AssetLib/FBX/FBXBinaryTokenizer.cpp`
- **Function**: `ReadScope()` (line ~334), `ReadString()` (line ~154)

## Description

The FBX binary tokenizer in Assimp recursively calls `ReadScope()` for each nested node in the FBX binary file format. There is no depth limit on this recursion. A crafted FBX file with ~4000+ levels of nested nodes exhausts the call stack, causing a `SIGSEGV` (stack overflow) detected by AddressSanitizer.

The vulnerability is trivially exploitable: the file format allows arbitrary nesting depth, and the parser follows it without bound. Each level of recursion adds a stack frame of ~200+ bytes, so ~4000 levels is sufficient to overflow a default 8MB stack.

## Affected Versions

Tested on the Assimp version in the `revelio/assimp:latest` ARVO image. The vulnerable code path has been present since early FBX binary support was added and remains in the current Assimp `master` branch.

## Reproduction

```bash
# Generate the PoC
python3 gen_poc.py

# Run against the fuzzer
./reproduce.sh
```

## Root Cause

`FBXBinaryTokenizer.cpp:ReadScope()` calls itself for every child node block without checking recursion depth. The fix is to add a maximum depth parameter and bail out when exceeded.

## Deduplicated PoCs

The following PoCs from the original set all trigger this same bug:
- `poc1_deep_nesting.fbx` (depth=30000)
- `poc_depth_4000.fbx`, `poc_depth_5000.fbx`, `poc_depth_10000.fbx`

The representative PoC uses depth=4000, the minimum required to trigger the crash.
