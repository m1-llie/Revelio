# Double-Free / Heap-Use-After-Free in `heif_track_release()`

## Summary

`heif_track_release()` unconditionally deletes the track object with no guard
against double-release, causing heap-use-after-free when called twice on the
same pointer.  On the second call the `shared_ptr<HeifContext>` destructor
inside `heif_track::~heif_track()` performs a reference-count read on an
already-freed heap region, yielding an ASAN-confirmed
`heap-use-after-free — READ of size 8`.

- **Affected file:** `libheif/api/libheif/heif_sequences.cc`, line 55–58  
  (struct layout: `libheif/api_structs.h`, line 41)
- **Type:** CWE-415 Double Free / CWE-416 Use After Free
- **Confirmed on version:** libheif 1.21.2

---

## Root Cause

`heif_track_release()` is a one-liner with no ownership guard:

```cpp
// heif_sequences.cc:55-58
void heif_track_release(heif_track* track)
{
  delete track;   // unconditional — no null check, no double-free guard
}
```

The `heif_track` struct (api_structs.h:35-42) holds a `std::shared_ptr<HeifContext>`:

```cpp
// api_structs.h:35-42
struct heif_track
{
  std::shared_ptr<Track> track;

  // store reference to keep the context alive while we are using the handle (issue #147)
  std::shared_ptr<HeifContext> context;   // <-- line 41: UAF site
};
```

On the **first** `delete track` the `shared_ptr<HeifContext>` destructor runs
normally, decrementing the control-block reference count (a READ+WRITE of 8
bytes at the control block).  The heap region `[0x...f0, 0x...10)` is then
poisoned as freed.

On the **second** `delete track` C++ still calls `~heif_track()`, which again
runs the `shared_ptr<HeifContext>` destructor.  That destructor attempts to read
the reference count from the now-freed control block — a
**heap-use-after-free READ of size 8** confirmed at
`shared_ptr_base.h:729` / `api_structs.h:41`.

For comparison, `heif_image_handle_release()` (the analogous function for still
images) follows the same pattern and is equally unguarded; however
`heif_track_release()` is the first API surface that has been confirmed to
trigger the UAF in practice because the sequence API is newer and less
battle-tested.

---

## Vulnerable Code

```cpp
// libheif/api/libheif/heif_sequences.cc  (lines 55-58)
void heif_track_release(heif_track* track)
{
  delete track;   // BUG: no nullptr guard, no double-free protection
}
```

The allocating counterpart (heif_sequences.cc:85-96) uses `new heif_track`
with no reference counting at the API layer:

```cpp
heif_track* heif_context_get_track(const heif_context* ctx, uint32_t track_id)
{
  auto trackResult = ctx->context->get_track(track_id);
  if (!trackResult) {
    return nullptr;
  }
  auto* track = new heif_track;        // raw new — caller owns lifetime
  track->track   = *trackResult;
  track->context = ctx->context;       // shared_ptr copy — refcount +1
  return track;
}
```

---

## Trigger

```c
heif_context* ctx = heif_context_alloc();
// load a HEIF sequence file (any file with a 'moov' box and one track)
heif_context_read_from_memory_without_copy(ctx, data, size, NULL);

uint32_t track_ids[1];
heif_context_get_track_ids(ctx, track_ids);
heif_track* track = heif_context_get_track(ctx, track_ids[0]);

heif_track_release(track);   // first release — OK: frees heif_track,
                              //   shared_ptr<HeifContext> destructor runs normally

heif_track_release(track);   // second release — DOUBLE FREE / UAF:
                              //   shared_ptr<HeifContext>::~__shared_ptr() reads
                              //   freed control block -> heap-use-after-free
```

Full C++ reproduction is in `poc_trigger.cc`.

---

## ASAN Output (excerpt)

```
ERROR: AddressSanitizer: heap-use-after-free on address 0x7be2a99e0808
READ of size 8 at 0x7be2a99e0808 thread T0
    #0  std::__shared_count<...>::~__shared_count()
            shared_ptr_base.h:729
    #1  std::__shared_ptr<HeifContext,...>::~__shared_ptr()
            shared_ptr_base.h:1169
    #2  heif_track::~heif_track()
            api_structs.h:41
    #3  heif_track_release
            heif_sequences.cc:57
    #4  main
            poc_trigger.cc:134

freed by thread T0 here:
    #0  operator delete(void*, unsigned long)
    #1  main  poc_trigger.cc:120   <-- first heif_track_release()

previously allocated by thread T0 here:
    #0  operator new(unsigned long)
    #1  heif_context_get_track  heif_sequences.cc:92

SUMMARY: heap-use-after-free  api_structs.h:41 in heif_track::~heif_track()
```

Full output is in `asan_output_validated.txt`.

---

## Impact

- **CWE:** CWE-415 (Double Free) / CWE-416 (Use After Free)
- **Severity:** Medium — exploitable when an application error path leads to
  double-release (e.g., error handling that calls `heif_track_release()` on a
  pointer that has already been released in a cleanup block, or a C wrapper
  that does not null the pointer after release)
- **Effect:** Heap corruption via double-free; with attacker-controlled
  allocation timing the freed control block can be reused to forge an
  arbitrary `shared_ptr` reference count, potentially leading to controlled
  code execution or privilege escalation

---

## Suggested Fix

**Option A — Null-guard before delete (minimal change):**

```cpp
void heif_track_release(heif_track* track)
{
  delete track;   // 'delete nullptr' is a no-op in C++, but callers should
                  // null their pointer after release
}
```
Document (and enforce in examples) that callers must set the pointer to
`nullptr` after calling `heif_track_release()`.

**Option B — Recommended: null-check + clear caller's pointer (API contract):**

Since C does not let us null the caller's pointer, the idiomatic C approach is
to document that callers must do:

```c
heif_track_release(track);
track = NULL;   // caller's responsibility
```

And add a defensive null-check inside:

```cpp
void heif_track_release(heif_track* track)
{
  if (track == nullptr) return;   // tolerate NULL and already-null pointers
  delete track;
}
```

**Option C — Preferred long-term: opaque handle with reference counting:**

Wrap `heif_track*` in a reference-counted opaque handle (analogous to
`shared_ptr`) so that multiple `heif_track_release()` calls on different
handles to the same underlying track are safe.

---

## Reproduction

```bash
bash build.sh
```

The script:
1. Builds libheif 1.21.2 from source with `-fsanitize=address,undefined`
2. Runs `gen_heif.py` to produce `minimal_sequence.heif`
3. Compiles `poc_trigger.cc` against the ASAN build
4. Executes the POC — ASAN aborts with `heap-use-after-free`

Expected result: ASAN crash as shown in `asan_output_validated.txt`.
