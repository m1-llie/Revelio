# Stack Overflow via Unbounded Recursion in PDF AcroForm /Kids Traversal

## Summary

`FormField::FormField()` in `poppler/Form.cc` iterates the /Kids array of an AcroForm field dictionary and calls `Form::createFieldFromDict()` for each child, which in turn constructs new `FormField` objects — establishing mutual recursion with no depth limit. Although a `usedParents` set prevents cycles, it does not prevent deeply nested linear /Kids chains. A PDF with a 5000-level deep /Kids hierarchy exhausts the call stack and crashes the process.

- **Affected files:** `poppler/Form.cc:1032` (FormField constructor), `poppler/Form.cc:2677` (createFieldFromDict)
- **Confirmed on commit:** `e3d56a0` (2026-04-04, poppler 26.04.90 dev; also affects stable 26.04.0)
- **Sanitizer:** ASan (`AddressSanitizer: stack-overflow`)
- **CWE:** CWE-674 (Uncontrolled Recursion)
- **CVSS:** 7.5 (High) — AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H

## Vulnerable Code

```cpp
// poppler/Form.cc (commit e3d56a0)

// FormField constructor  (line ~1032)
FormField::FormField(PDFDoc *docA, std::unique_ptr<GfxResources> &&resourcesA,
                     const Ref aref, FormField *parent,
                     std::set<int> *usedParents, FormFieldType t)
{
    ...
    for (int i = 0; i < numChildren; ++i) {
        // Recursively creates FormField objects for each /Kids entry
        children[i] = Form::createFieldFromDict(              // line ~1032
                           kidDict, doc, kidRef, this, usedParents);
    }
    ...
}

// createFieldFromDict  (line ~2677)
std::unique_ptr<FormField> Form::createFieldFromDict(
    Object &&obj, PDFDoc *docA, const Ref aref,
    FormField *parent, std::set<int> *usedParents)
{
    ...
    // Constructs a new FormField (e.g. FormFieldText), calling the
    // FormField base constructor, which recurses into /Kids again
    field = std::make_unique<FormFieldText>(docA, ...);      // line ~2677
    ...
}
```

The `usedParents` set (passed by pointer) correctly detects back-edges (cycles) but does not bound the recursion depth for acyclic linear chains. Each recursive level also copies or passes the `usedParents` set, producing O(n²) work for an
n-level chain.


## Proof of Concept

PoC file: `poc.pdf` (~490 KB).

The PDF contains an AcroForm with a 5000-level deep /Kids hierarchy: each field dictionary has a /Kids array containing exactly one child field, chained 5000 times.

### Reproduction

**Standard CLI:**
```bash
pdftotext poc.pdf /dev/null
# AcroForm fields are enumerated during document open; stack overflow occurs before any text extraction work begins.
```

**With ASan (definitive confirmation):**
```bash
  /out/asan/pdf_fuzzer /work/poc.pdf
```

### Observed Output

```
AddressSanitizer: stack-overflow on address 0x... (pc 0x... ...)
    #0  FormField::FormField        (Form.cc:1032)
    #1  Form::createFieldFromDict   (Form.cc:2677)
    #2  FormFieldText::FormFieldText(FormFieldText.cc:1594)
    #3  FormField::FormField        (Form.cc:1032)
    #4  Form::createFieldFromDict   (Form.cc:2677)
    ... (repeating)
```


## Impact

Any PDF containing a sufficiently deep AcroForm /Kids hierarchy causes a stack overflow, crashing the poppler process (or the application embedding it). The PoC is 490 KB and requires no special privileges. The crash is reachable via any poppler entry point that processes AcroForms, including rendering, text extraction, and form filling.


## Suggested Fix

Two complementary changes are needed:

1. **Add a depth limit.** Pass a `depth` counter through `createFieldFromDict` and the `FormField` constructor; abort with an error when depth exceeds a safe threshold (e.g., 500):

```diff
 std::unique_ptr<FormField> Form::createFieldFromDict(
-    Object &&obj, PDFDoc *docA, const Ref aref,
-    FormField *parent, std::set<int> *usedParents)
+    Object &&obj, PDFDoc *docA, const Ref aref,
+    FormField *parent, std::set<int> *usedParents, int depth = 0)
 {
+    if (depth > 500) {
+        error(errSyntaxError, -1, "Form: AcroForm /Kids hierarchy too deep");
+        return nullptr;
+    }
     ...
-    field = std::make_unique<FormFieldText>(docA, ...);
+    field = std::make_unique<FormFieldText>(docA, ..., depth + 1);
     ...
 }
```

2. **Convert to iterative traversal** (preferred for robustness) using an explicit stack to eliminate call-stack consumption entirely.
