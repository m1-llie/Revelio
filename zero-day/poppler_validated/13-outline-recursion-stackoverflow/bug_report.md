# Stack Overflow via Unbounded Recursion in PDF Outline /First Chain Traversal (CWE-674)

## Summary

`toc_item_private::load_children()` in `cpp/poppler-toc.cpp` and
`newHtmlOutlineLevel()` in `utils/HtmlOutputDev.cc` both recurse into PDF outline
(bookmark) item children without any depth limit. A PDF containing a 100,000-level
deep `/First` chain in the outline dictionary exhausts the call stack. At 1 MB stack
size (as used in constrained environments and as set by `ulimit -s 1024`), the crash
occurs at approximately depth 21,000.

- **Affected files:** `cpp/poppler-toc.cpp:84` (load_children), `utils/HtmlOutputDev.cc:1729` (newHtmlOutlineLevel)
- **Confirmed on commit:** `e3d56a0` (2026-04-04, poppler 26.04.90)
- **Sanitizer:** ASan (with `ulimit -s 1024`)
- **CWE:** CWE-674 (Uncontrolled Recursion)
- **CVSS:** 7.5 (High) — AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H

---

## Vulnerable Code

### cpp/poppler-toc.cpp (line ~84)

```cpp
// toc_item_private::load_children() — no depth parameter, no depth check
void toc_item_private::load_children()
{
    ...
    for (OutlineItem *item : *items) {
        item->open();                        // triggers child loading
        toc_item *child = new toc_item(...);
        child->d->load_children();           // line ~84: unconditional recursion
        children.push_back(child);
    }
    ...
}
```

### utils/HtmlOutputDev.cc (line ~1729)

```cpp
// newHtmlOutlineLevel() — takes a 'level' param but never checks a maximum
void HtmlOutputDev::newHtmlOutlineLevel(const std::vector<OutlineItem *> *items,
                                         int level)
{
    for (OutlineItem *item : *items) {
        item->open();
        if (item->hasKids() && item->getKids()) {
            newHtmlOutlineLevel(item->getKids(), level + 1);  // line ~1729: no max check
        }
    }
}
```

Neither function checks a depth limit before recursing. The call chain through the
core outline API is: `OutlineItem::readItemList` → `OutlineItem::open` → repeating.

---

## Proof of Concept

PoC file: `poc.pdf` (located in this directory, ~10 MB).

The PDF contains an outline (Outlines dictionary) with a 100,000-level deep
linear `/First` chain: each outline item points to a single child via `/First`,
chained 100,000 times.

### Reproduction

The standard OSS-Fuzz fuzzers (`pdftotext`, `pdf_draw_fuzzer`, etc.) do not
invoke `create_toc()` or `newHtmlOutlineLevel()`. Reproduction requires either:

**Option A — Custom binary using poppler-cpp API:**
```cpp
// custom_poc.cpp
#include <poppler-document.h>
#include <poppler-toc.h>
int main(int argc, char *argv[]) {
    auto doc = poppler::document::load_from_file(argv[1]);
    if (doc) {
        auto toc = doc->create_toc();   // triggers load_children() recursion
        delete toc;
        delete doc;
    }
    return 0;
}
```
```bash
# Build against poppler with ASan, then:
ulimit -s 1024
ASAN_OPTIONS="detect_stack_use_after_return=0" ./custom_poc poc.pdf
```

**Option B — pdftohtml (exercises newHtmlOutlineLevel):**
```bash
docker run --rm \
  -v /scr2/yiwei/vul-agent/zero-day/poppler_validated/13-outline-recursion-stackoverflow:/work \
  vulagent/poppler:latest \
  bash -c "ulimit -s 1024 && pdftohtml /work/poc.pdf /tmp/out"
```

### Observed Output (ASan, ulimit -s 1024)

```
AddressSanitizer: stack-overflow on address 0x... (pc 0x... ...)
    #0  OutlineItem::readItemList (Outline.cc:...)
    #1  OutlineItem::open         (Outline.cc:...)
    #2  OutlineItem::readItemList (Outline.cc:...)
    #3  OutlineItem::open         (Outline.cc:...)
    ... (repeating, crash at ~depth 21,000 with 1 MB stack)
```

---

## Impact

Any application using the poppler-cpp `create_toc()` API or `pdftohtml` that
processes a PDF with a deeply nested outline crashes with a stack overflow.
The PoC requires no special privileges. The default Linux stack size (8 MB)
shifts the crash depth to approximately ~168,000 levels; the 100,000-level PoC
reliably crashes at 1 MB stack and can be scaled to crash at any stack size.

---

## Suggested Fix

Two changes are needed, one per affected function:

1. **Add a depth limit to `load_children()`:**

```diff
-void toc_item_private::load_children()
+void toc_item_private::load_children(int depth = 0)
 {
+    if (depth > 500) {
+        error(errSyntaxWarning, -1, "TOC: outline hierarchy too deep, truncating");
+        return;
+    }
     ...
-    child->d->load_children();
+    child->d->load_children(depth + 1);
     ...
 }
```

2. **Add a depth check to `newHtmlOutlineLevel()`:**

```diff
 void HtmlOutputDev::newHtmlOutlineLevel(
     const std::vector<OutlineItem *> *items, int level)
 {
+    if (level > 500) return;
     ...
 }
```

For production robustness, converting both functions to iterative traversal
using an explicit stack is preferred over a depth counter.
