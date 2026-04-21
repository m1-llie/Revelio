# Heap-buffer-overflow in cairo `find_name()` with malformed TrueType `name` table

## Summary

`find_name()` in `cairo-truetype-subset.c` reads a 2-byte value from `data + record->offset` without checking that the offset is still inside the allocated `name` table buffer. A malformed embedded TrueType font therefore triggers a heap out-of-bounds read when cairo subsets the font during PDF surface finalization.

The bug is reachable through cairo's standard public API:

```
cairo_surface_destroy()        ← public API triggers surface finalization
  → cairo_surface_finish()
  → _cairo_pdf_surface_finish()
  → _cairo_pdf_surface_emit_font_subsets()
  → cairo_truetype_subset_init_internal()
  → _cairo_truetype_read_font_name()
  → find_name()                ← heap-buffer-overflow HERE
```

Any application that: (1) loads a PDF containing a TrueType font with a crafted `name` table, and (2) re-renders it to a cairo PDF surface， will crash with a heap-buffer-overflow when `cairo_surface_destroy()` is called.

## Affected code

- **File:** `cairo/src/cairo-truetype-subset.c`
- **Function:** `find_name()`
- **Line:** 1462
- **Vulnerable read:**

```c
uint16_t len = be16_to_cpu(*(uint16_t *)(data + record->offset));
```

`record->offset` is read directly from the TrueType `name` table in the font file and is not checked against the string storage size before the pointer is dereferenced.

## Tested version

- **Cairo:** git master (≥ 1.18.4) — latest stable release is **cairo 1.18.4** (2025-03-08)
- The bug is present in the `find_name()` code at `cairo-truetype-subset.c:1462`

## Environment

- OS: Linux x86_64
- Cairo version: git master (≥ 1.18.4), built from source with AddressSanitizer
- Compiler: `clang++`
- Sanitizer: AddressSanitizer (`-fsanitize=address`)

## Reproduction

The attached `poc.pdf` contains an embedded TrueType font with a truncated `name` table whose `record->offset` points past the end of the string storage area.

**Option A: using the poppler OSS-Fuzz fuzz target as a program entry point**:
```bash
  /out/asan/annot_fuzzer /tmp/poc.pdf
```

**Option B: standalone cairo C program**:
```c
#include <cairo/cairo.h>
#include <cairo/cairo-pdf.h>
#include <cairo/cairo-ft.h>
#include <ft2build.h>
#include FT_FREETYPE_H

int main(void) {
    /* 1. Create a cairo PDF surface */
    cairo_surface_t *surface = cairo_pdf_surface_create("out.pdf", 200, 200);
    cairo_t *cr = cairo_create(surface);

    /* 2. Load the malformed TrueType font via FreeType */
    FT_Library ft;
    FT_Face face;
    FT_Init_FreeType(&ft);
    FT_New_Face(ft, "poc_font.ttf", 0, &face);  /* extract from poc.pdf */
    cairo_font_face_t *ff = cairo_ft_font_face_create_for_ft_face(face, 0);
    cairo_set_font_face(cr, ff);

    /* 3. Draw text — marks the font for subsetting */
    cairo_move_to(cr, 10, 100);
    cairo_show_text(cr, "A");

    /* 4. Destroy — triggers cairo_surface_finish → find_name() crash */
    cairo_font_face_destroy(ff);
    cairo_destroy(cr);
    cairo_surface_destroy(surface);  /* <-- heap-buffer-overflow here */
    return 0;
}
```

## ASan output

```
ERROR: AddressSanitizer: heap-buffer-overflow on address 0x7db7af6e6ccc
READ of size 2 at 0x7db7af6e6ccc thread T0
    #0 find_name /src/cairo/_builddir/../src/cairo-truetype-subset.c:1462:27
    #1 _cairo_truetype_read_font_name         cairo-truetype-subset.c:1591
    #2 _cairo_truetype_font_create            cairo-truetype-subset.c:242
    #3 cairo_truetype_subset_init_internal    cairo-truetype-subset.c:1148
    #4 _cairo_pdf_surface_emit_truetype_font_subset
    #5 _cairo_pdf_surface_emit_font_subsets
    #6 _cairo_pdf_surface_finish              cairo-pdf-surface.c:2711
    #7 cairo_surface_finish                   cairo-surface.c:1092
    #8 cairo_surface_destroy                  cairo-surface.c:978

0x7db7af6e6ccc is located 0 bytes after 2124-byte region [0x7db7af6e6480,0x7db7af6e6ccc)
```

## Impact

- **CWE-122**: Heap-based Buffer Overflow (out-of-bounds read)
- **CVSS**: ~7.8 (High). Attacker-controlled font data in a PDF triggers a heap out-of-bounds read in any application that renders the PDF to a cairo PDF surface
- Any document-conversion, print, or PDF-export application using cairo is affected (e.g., evince "Print to PDF", Inkscape, LibreOffice export)

## Suggested fix

In `find_name()`, validate `record->offset` and `record->length` against the size of the string storage area before dereferencing `data + record->offset`:

```c
/* Before reading: check offset is within the string storage */
if (record->offset + sizeof(uint16_t) > string_storage_size)
    return CAIRO_INT_STATUS_UNSUPPORTED;  /* or skip this record */
uint16_t len = be16_to_cpu(*(uint16_t *)(data + record->offset));
```

Similarly validate `record->offset + len` before reading the full string body.