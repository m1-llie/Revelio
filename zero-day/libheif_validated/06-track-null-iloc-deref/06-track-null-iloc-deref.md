# NULL Pointer Dereference in Track Parsing via Missing `iloc` Box

## Summary

A NULL pointer dereference vulnerability exists in the libheif HEIF sequence
(ISOBMFF track) parser. When a `trak` box contains a `meta` box that includes
an `iinf` item of type `uri ` with the GIMI content-ID URN, but does **not**
include an `iloc` box, the code at `track.cc:478` dereferences the NULL `iloc`
pointer unconditionally.

- **Affected file:** `libheif/sequences/track.cc`, line 478
- **Crash function:** `Track::load()` calling `iloc->read_data(...)`
- **Confirmed version:** libheif 1.21.2
- **Impact:** NULL pointer dereference (CWE-476); reliably triggered by a
  malicious HEIF sequence file containing a `trak > meta` with `iinf(uri )`
  but no `iloc` box — causes immediate process crash (DoS).

## Root Cause

In `Track::load()` (`track.cc`, lines 465–492), the code retrieves the `iloc`
child box from the `meta` box (line 466), but never checks whether the pointer
is NULL before using it at line 478:

```cpp
// track.cc:465-490
if (auto meta = trak_box->get_child_box<Box_meta>()) {
    auto iloc = meta->get_child_box<Box_iloc>();   // line 466 — may return nullptr
    auto idat = meta->get_child_box<Box_idat>();

    auto iinf = meta->get_child_box<Box_iinf>();
    if (iinf) {
      auto infe_boxes = iinf->get_child_boxes<Box_infe>();
      for (const auto& box : infe_boxes) {
        if (box->get_item_type_4cc() == fourcc("uri ") &&
            box->get_item_uri_type() == "urn:uuid:15beb8e4-944d-5fc6-a3dd-cb5a7e655c73") {
          heif_item_id id = box->get_item_ID();

          std::vector<uint8_t> data;
          Error err = iloc->read_data(   // line 478 — CRASH: iloc is NULL
              id,
              m_heif_context->get_heif_file()->get_reader(),
              idat, &data,
              m_heif_context->get_security_limits());
```

`get_child_box<Box_iloc>()` returns `nullptr` when the `meta` box contains no
`iloc` child.  The `iinf` / `infe` existence check does not imply an `iloc`
must exist, and no guard is present before the dereference.

## Vulnerable Code

```cpp
// libheif/sequences/track.cc, lines 465-490
if (auto meta = trak_box->get_child_box<Box_meta>()) {
    auto iloc = meta->get_child_box<Box_iloc>();   // may be nullptr — NOT checked
    auto idat = meta->get_child_box<Box_idat>();

    auto iinf = meta->get_child_box<Box_iinf>();
    if (iinf) {
      auto infe_boxes = iinf->get_child_boxes<Box_infe>();
      for (const auto& box : infe_boxes) {
        if (box->get_item_type_4cc() == fourcc("uri ") &&
            box->get_item_uri_type() == "urn:uuid:15beb8e4-944d-5fc6-a3dd-cb5a7e655c73") {
          heif_item_id id = box->get_item_ID();
          std::vector<uint8_t> data;
          // *** NULL dereference when iloc == nullptr ***
          Error err = iloc->read_data(id, ..., &data, ...);  // line 478
        }
      }
    }
}
```

## Trigger

The crash is triggered by a minimal HEIF/ISOBMFF file with the following
structure (637 bytes):

```
ftyp  (major_brand=msf1, compatible_brands=[msf1, isom])
moov
  mvhd
  trak
    tkhd
    mdia
      mdhd
      hdlr  (handler_type=meta)
      minf
        nmhd
        stbl
          stsd  (entry: urim sample entry)
          stts  (0 entries)
          stsc  (1 entry)
          stco  (0 entries)
          stsz  (0 samples)
    meta                             <-- trak-level meta box
      hdlr  (handler_type=uri )
      iinf  (item_count=1)
        infe  (version=2, item_ID=1, item_type=uri ,
               item_uri_type=urn:uuid:15beb8e4-944d-5fc6-a3dd-cb5a7e655c73)
      (NO iloc box)                  <-- triggers the NULL deref
```

The `ftyp` with `msf1`/`isom` brands causes libheif to call
`parse_heif_sequences()`, which calls `Track::alloc_track()`, which calls
`Track_Metadata::load()` and ultimately `Track::load()` — reaching the
vulnerable code path.

## ASAN Crash Output

```
AddressSanitizer:DEADLYSIGNAL
==1==ERROR: AddressSanitizer: SEGV on unknown address 0x0000000000a0
==1==The signal is caused by a READ memory access.
    #0 Box_iloc::read_data(...) /src/libheif/libheif/box.cc:1782
    #1 Box_iloc::read_data(...) /src/libheif/libheif/box.cc:1770
    #2 Track::load(...)         /src/libheif/libheif/sequences/track.cc:478
    #3 Track_Metadata::load(...)  /src/libheif/libheif/sequences/track_metadata.cc:35
    #4 Track::alloc_track(...)  /src/libheif/libheif/sequences/track.cc:682
    #5 HeifContext::interpret_heif_file_sequences()  /src/libheif/libheif/context.cc:1952
    ...
```

## Impact

- **CWE:** CWE-476 (NULL Pointer Dereference)
- **Severity:** Medium-High
- **Effect:** Denial of Service — the process crashes immediately upon parsing
  the malformed file.
- **Attack vector:** A remote attacker can craft a ~637-byte HEIF sequence file
  and deliver it to any application using libheif for parsing (image viewers,
  media players, browsers with libheif support).  No user interaction beyond
  opening/previewing the file is required.

## Suggested Fix

Add a null-check for `iloc` before attempting to dereference it inside the
`infe` loop.  If the `iloc` box is absent, the track data cannot be read and
an appropriate error should be returned:

```cpp
if (auto meta = trak_box->get_child_box<Box_meta>()) {
    auto iloc = meta->get_child_box<Box_iloc>();
    auto idat = meta->get_child_box<Box_idat>();

    auto iinf = meta->get_child_box<Box_iinf>();
    if (iinf) {
      auto infe_boxes = iinf->get_child_boxes<Box_infe>();
      for (const auto& box : infe_boxes) {
        if (box->get_item_type_4cc() == fourcc("uri ") &&
            box->get_item_uri_type() == "urn:uuid:15beb8e4-944d-5fc6-a3dd-cb5a7e655c73") {
          // FIX: guard against missing iloc box
          if (!iloc) {
            return Error{heif_error_Invalid_input,
                         heif_suberror_Unspecified,
                         "Track meta box contains uri infe item but no iloc box."};
          }
          heif_item_id id = box->get_item_ID();
          std::vector<uint8_t> data;
          Error err = iloc->read_data(id, ..., &data, ...);
          ...
        }
      }
    }
}
```

## Reproduction

```bash
bash build.sh
```
