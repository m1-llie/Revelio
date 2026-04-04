# GPAC IPMP Tool Descriptor Heap Buffer Overflow

## Vulnerability

- **CWE**: CWE-122 (Heap-based Buffer Overflow)
- **Type**: Heap buffer overflow (write)
- **Severity**: High (potential code execution)
- **Component**: GPAC multimedia framework
- **File**: `src/odf/odf_code.c`
- **Function**: `gf_odf_read_ipmp_tool()` (line ~3340)

## Description

The IPMP Tool descriptor (ODF tag 0x61) contains a `num_alternate` field that specifies how many alternate tool IDs to read. These are stored in a fixed-size array `specificToolID[MAX_IPMP_ALT_TOOLS]` where `MAX_IPMP_ALT_TOOLS=20`. The parser reads `num_alternate` entries from the bitstream without checking against this limit.

Setting `num_alternate=30` causes 10 extra 16-byte entries (160 bytes) to be written past the end of the heap-allocated array, resulting in a heap buffer overflow.

**Note**: This code path is disabled in OSS-Fuzz builds because `GPAC_MINIMAL_ODF` is defined, which excludes IPMP parsing. However, it affects any full (non-minimal) GPAC build, including official release binaries.

## Affected Versions

Tested against the GPAC source in the `vulagent/gpac:latest` ARVO image. The vulnerable code path exists in all GPAC versions that include IPMP support.

## Reproduction

```bash
# Requires rebuilding GPAC with GPAC_MINIMAL_ODF disabled
./reproduce.sh
```

The reproduce script automatically patches the build to disable `GPAC_MINIMAL_ODF`, recompiles the relevant ODF modules, builds a custom harness, and runs the PoC.

## Root Cause

`gf_odf_read_ipmp_tool()` reads `num_alternate` from the bitstream and iterates that many times to fill `specificToolID[]`, without bounds-checking against `MAX_IPMP_ALT_TOOLS`. The fix is to clamp `num_alternate` to `MAX_IPMP_ALT_TOOLS` before the read loop.
