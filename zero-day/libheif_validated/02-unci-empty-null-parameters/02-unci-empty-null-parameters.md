# NULL Pointer Dereference in `heif_context_add_empty_unci_image()` via Unvalidated `parameters`

## Summary

`heif_context_add_empty_unci_image()` in `libheif/api/libheif/heif_uncompressed.cc`
validates `prototype` and `out_unci_image_handle` for NULL but omits the same check
for `parameters`. The pointer is forwarded directly to `add_unci_item()`, which
unconditionally dereferences it at line 113, causing a **NULL pointer dereference**
(UBSan + ASAN SEGV).

- **Affected file:** `libheif/libheif/api/libheif/heif_uncompressed.cc` (API entry point)
- **Crash site:** `libheif/libheif/image-items/unc_image.cc:113`
- **Function:** `ImageItem_uncompressed::add_unci_item()`
- **Confirmed on version:** libheif 1.21.2 (latest release, 2026-04-17)
- **Build requirement:** `WITH_UNCOMPRESSED_CODEC=ON`
- **Impact:** Denial of service (process crash); CWE-476 NULL Pointer Dereference

---

## Root Cause

`heif_context_add_empty_unci_image()` performs partial null-checks:

```cpp
// libheif/api/libheif/heif_uncompressed.cc:787-801
heif_error heif_context_add_empty_unci_image(
    heif_context* ctx,
    const heif_unci_image_parameters* parameters,   // ← no NULL check
    const heif_encoding_options* encoding_options,
    const heif_image* prototype,
    heif_image_handle** out_unci_image_handle)
{
#if WITH_UNCOMPRESSED_CODEC
  if (prototype == nullptr || out_unci_image_handle == nullptr) {
    return heif_error_null_pointer_argument;   // checks prototype and handle...
  }
  // ...
  unciImageResult = ImageItem_uncompressed::add_unci_item(
      ctx->context.get(), parameters, ...);    // ...but passes parameters unguarded
```

Inside `add_unci_item()` at `unc_image.cc:113`:

```cpp
if (parameters->image_width % parameters->tile_width != 0 ||   // CRASH: NULL deref
    parameters->image_height % parameters->tile_height != 0) {
```

When `parameters == nullptr`, the member access triggers UBSan
`"member access within null pointer"` followed by an ASAN SEGV at address `0x4`
(offset of `image_width` within the struct).

---

## Vulnerable Code

**`libheif/api/libheif/heif_uncompressed.cc` (API guard, line ~791):**
```cpp
if (prototype == nullptr || out_unci_image_handle == nullptr) {
    // BUG: parameters is not checked here
    return heif_error_null_pointer_argument;
}
```

**`libheif/image-items/unc_image.cc:113` (crash site):**
```cpp
if (parameters->image_width % parameters->tile_width != 0 ||  // ← NULL deref
    parameters->image_height % parameters->tile_height != 0) {
```

---

## Trigger

```cpp
heif_context* ctx = heif_context_alloc();
heif_image* proto = /* valid image */;
heif_image_handle* out = nullptr;

// parameters = nullptr → crash at unc_image.cc:113
heif_context_add_empty_unci_image(ctx, /*parameters=*/nullptr, nullptr, proto, &out);
```

---

## Impact

- **Type:** NULL Pointer Dereference (CWE-476)
- **Effect:** Process crash (denial of service)
- **Severity:** Low–Medium
- **Reachable via:** Direct C API call with `parameters = NULL`; not reachable via file parsing
- **Affected callers:** Any application using the uncompressed codec write path that
  fails to validate user-supplied `parameters` before forwarding to libheif

---

## Suggested Fix

Add `parameters` to the existing null guard in `heif_context_add_empty_unci_image()`:

```cpp
if (prototype == nullptr || out_unci_image_handle == nullptr || parameters == nullptr) {
    return heif_error_null_pointer_argument;
}
```

Alternatively, add the check at the top of `add_unci_item()` for defence in depth.

---

## Reproduction

```bash
bash build.sh
# Expected output:
# unc_image.cc:113:19: runtime error: member access within null pointer
# AddressSanitizer: SEGV on unknown address 0x000000000004
```

See `poc_trigger.cc` for the minimal reproducer and `asan_output_validated.txt` for
the confirmed crash output.
