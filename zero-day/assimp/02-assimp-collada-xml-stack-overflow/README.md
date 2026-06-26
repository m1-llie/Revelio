# Assimp Collada/pugixml XML Parsing Stack Overflow

## Vulnerability

- **CWE**: CWE-674 (Uncontrolled Recursion)
- **Type**: Stack-based buffer overflow via uncontrolled recursion
- **Severity**: Medium (DoS / potential code execution)
- **Component**: Assimp (Open Asset Import Library) via pugixml
- **File**: `contrib/pugixml/src/pugixml.cpp`
- **Function**: `strequal()` (line ~251), called during recursive XML parsing

## Description

Deeply nested XML elements in a COLLADA file cause pugixml's internal XML parser to recurse without bound. The stack is exhausted during XML parsing itself, before Assimp's own Collada parser gets a chance to impose depth limits. A file with ~5000 levels of `<animation>` nesting (or `<node>` nesting) is sufficient to trigger the crash.

This is distinct from the `BuildHierarchy` recursion (vuln #3) — this crash happens during XML parsing, not during scene graph construction.

## Affected Versions

Tested on the Assimp version in the `revelio/assimp:latest` ARVO image. Affects any Assimp build using the bundled pugixml.

## Reproduction

```bash
python3 gen_poc.py
./reproduce.sh
```

## Root Cause

pugixml recursively parses nested XML elements without a depth limit. The fix should either patch pugixml to enforce a maximum parsing depth, or pre-scan the XML for excessive nesting before handing it to pugixml.

## Deduplicated PoCs

The following PoCs from the original set all trigger this same bug:
- `poc4_collada_recursion.dae` (deep `<node>` nesting)
- `poc6_anim_recursion.dae` (deep `<animation>` nesting)
- `poc13_anim_with_channel.dae` (deep `<animation>` nesting with channel data)
- `poc_collada_1000.dae` through `poc_collada_3000.dae` (depth variants; 3000 crashes)

The representative PoC uses `<animation>` nesting at depth=5000.
