# Bug Report: Heap Buffer Overflow in `find_name()` — Malformed TrueType Font Name Table

- **ID**: cairo-4
- **CWE**: CWE-125 (Out-of-bounds Read) / CWE-122 (Heap-based Buffer Overflow)
- **Severity**: High (CVSS 7.8)
- **Sanitizer**: ASan
- **Status**: Confirmed

---

## Summary

`find_name()` in `cairo/src/cairo-truetype-subset.c` (line 1462) performs a 2-byte
out-of-bounds read when processing a TrueType font with a malformed (truncated or
corrupt) `name` table. The function's caller, `_cairo_truetype_read_font_name()`,
allocates a buffer sized from the raw `name` table length declared in the font file but
does not validate individual name record offsets and lengths before `find_name()` uses
them to index into the buffer. An attacker-supplied PDF containing such a font triggers
the overflow when poppler's annotation rendering pipeline embeds the font via
`_cairo_pdf_surface_emit_truetype_font_subset`.

**Environment**

| Item | Value |
|------|-------|
| Cairo version | built from source as part of OSS-Fuzz poppler setup (alongside poppler 26.04.90) |
| Poppler version | 26.04.90 |
| Compiler | clang with ASan (`-fsanitize=address`) |
| Fuzzer binary | `/out/asan/annot_fuzzer` |

---

## Vulnerable Code

**File**: `cairo/src/cairo-truetype-subset.c`, line 1462

```c
static cairo_int_status_t
find_name(tt_name_t *name, int name_id, int platform, int encoding,
          char **str_out, int *len_out)
{
    ...
    for (i = 0; i < be16_to_cpu(name->num_records); i++) {
        tt_name_record_t *record = &name->records[i];
        ...
        /* line 1462: reads 2 bytes from (data + offset) without bounds check */
        uint16_t len = be16_to_cpu(*(uint16_t *)(data + record->offset));
        ...
    }
}
```

The `data` pointer points to the string storage area of the `name` table. `record->offset`
and `record->length` come directly from the font file without validation. When the declared
`offset + 2` exceeds the allocated buffer size, the read is out of bounds.

**ASan diagnostic**

```
==<pid>==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x... at pc 0x...
READ of size 2 at 0 bytes past end of 2124-byte region
    #0 find_name /src/cairo/_builddir/../src/cairo-truetype-subset.c:1462:27
    #1 _cairo_truetype_read_font_name /src/cairo/_builddir/../src/cairo-truetype-subset.c:1591
    #2 _cairo_truetype_font_create /src/cairo/_builddir/../src/cairo-truetype-subset.c:242
    #3 cairo_truetype_subset_init_internal /src/cairo/_builddir/../src/cairo-truetype-subset.c:1148
    #4 _cairo_pdf_surface_emit_truetype_font_subset
```

---

## Proof of Concept

### Trigger condition

A PDF containing an annotation (e.g., a text annotation or form field) that references
an embedded TrueType font whose `name` table is truncated. The `name` table must declare
one or more name records whose `offset` + 2 bytes exceeds the actual stored string data.

Constructing such a PDF:
1. Take any PDF with a TrueType-embedded font annotation.
2. Locate the TrueType font stream (a `/FontFile2` or inline TrueType blob).
3. In the `name` table, set a `nameRecord.offset` value such that
   `stringOffset + nameRecord.offset + nameRecord.length > tableSize`.
4. The declared table length in the `sfnt` directory entry can be left unchanged so the
   buffer is allocated at the original size but the record points beyond it.

### Reproduction steps

1. Build or pull the OSS-Fuzz poppler Docker image:
   ```bash
   docker pull vulagent/poppler:latest
   ```

2. Place the proof-of-concept PDF at a known host path, e.g. `/tmp/poc.pdf`.

3. Run the annotation fuzzer binary under ASan:
   ```bash
   docker run --rm \
     -v /tmp:/tmp \
     vulagent/poppler:latest \
     /out/asan/annot_fuzzer /tmp/poc.pdf
   ```

4. Observe the ASan report:
   ```
   AddressSanitizer: heap-buffer-overflow — READ of size 2 at 0 bytes past end of
   2124-byte region, in find_name cairo-truetype-subset.c:1462
   ```

### Call stack

```
find_name                                    (cairo-truetype-subset.c:1462)
_cairo_truetype_read_font_name               (cairo-truetype-subset.c:1591)
_cairo_truetype_font_create                  (cairo-truetype-subset.c:242)
cairo_truetype_subset_init_internal          (cairo-truetype-subset.c:1148)
_cairo_pdf_surface_emit_truetype_font_subset
annot_fuzzer / poppler annotation rendering pipeline
```

---

## Impact

- **Out-of-bounds read**: Up to 2 bytes of heap memory adjacent to the `name` table
  buffer are read. Depending on heap layout this may disclose addresses, canaries, or
  other font data, aiding further exploitation.
- **Denial of service**: ASan aborts the process. Without a sanitizer, the read may
  return arbitrary data causing downstream logic errors (wrong font name, failed
  subsetting, or crash from use of the corrupted value).
- **Heap grooming exploitation**: Although the overflow is read-only, carefully crafted
  heap layouts (common in fuzzer-driven exploit development) could position sensitive
  data at the overflow location. CWE-122 is listed as a secondary CWE because the
  category covers heap-region overreads as well as writes.
- **Attack vector**: Any application that uses cairo to embed TrueType fonts into a PDF
  output and processes attacker-supplied font data is affected. The poppler pathway is
  through annotation rendering, but any cairo PDF/PS/SVG backend that calls
  `cairo_truetype_subset_init_internal` with untrusted fonts is exposed.

---

## Suggested Fix

### 1. Validate each record before accessing string data in `find_name()`

```c
for (i = 0; i < be16_to_cpu(name->num_records); i++) {
    tt_name_record_t *record = &name->records[i];
    uint32_t offset = be16_to_cpu(record->offset);
    uint32_t length = be16_to_cpu(record->length);

    /* Bounds check: reject records that reach outside the table buffer */
    if (offset + length > table_size || offset + 2 > table_size)
        continue;

    /* Safe to access data[offset] now */
    ...
}
```

### 2. Propagate `table_size` to `find_name()`

`find_name()` currently does not receive the size of the string storage area. Add a
`size_t string_data_size` parameter and thread it through from
`_cairo_truetype_read_font_name()`, which knows the allocation size.

### 3. Add a fuzz regression test

Add the minimised PoC PDF as a seed corpus entry for `cairo-truetype-subset` fuzzing so
this class of malformed `name` table is covered by CI.
