# Assimp ColladaLoader::BuildHierarchy Stack Overflow

## Vulnerability

- **CWE**: CWE-674 (Uncontrolled Recursion)
- **Type**: Stack-based buffer overflow via uncontrolled recursion
- **Severity**: Medium (DoS / potential code execution)
- **Component**: Assimp (Open Asset Import Library)
- **File**: `code/AssetLib/Collada/ColladaLoader.cpp`
- **Function**: `BuildHierarchy()` (line ~235)

## Description

The Collada loader's `BuildHierarchy()` function recursively visits child nodes to construct the scene graph. If a COLLADA file contains circular `<instance_node>` references (e.g., nodeA references nodeB which references nodeA), the recursion never terminates and exhausts the stack.

This is distinct from the pugixml XML parsing recursion (vuln #2) — this crash happens during Assimp's scene graph construction phase, after XML parsing has completed successfully.

## Affected Versions

Tested on the Assimp version in the `revelio/assimp:latest` ARVO image.

## Reproduction

```bash
python3 gen_poc.py
./reproduce.sh
```

## Root Cause

`ColladaLoader::BuildHierarchy()` does not track visited nodes. Circular `<instance_node>` references create infinite recursion. The fix is to maintain a visited-node set and detect cycles.

## Deduplicated PoCs

The following PoCs from the original set trigger this same bug:
- `poc12_circular_instance.dae` (circular instance_node)
- `poc_collada_3000.dae` (deep linear node nesting, same crash site)

The representative PoC uses a minimal circular reference (2 nodes, 544 bytes).
