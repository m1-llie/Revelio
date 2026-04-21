# Silent Inverse Projection Failure in ISEA (`+proj=isea`) — No Error Code Set

> **Filing note:** Report **together with bug #07** in a single GitHub issue as two
> medium-severity API-behavior bugs.  See Issue 7 in `REPORTING_GUIDE.md`.

## Summary

The ISEA projection (`+proj=isea`) returns `{inf, inf}` from inverse projection for most non-default parameter combinations, **without setting any error code**. Callers checking `proj_errno()` after the call see `0` (success), giving them no way to detect the failure programmatically. This is a silent data-corruption / logic-error bug.

- **Affected file:** `src/projections/isea.cpp`
- **Confirmed on commit:** `324ed2119011d74665548afe445eacb99afb9753` (PROJ master, 2026-04-17); latest affected release: PROJ **9.8.1** (2026-04-10)
- **Sanitizer required:** None — observable via program output
- **Impact:** Silent data corruption — inverse coordinates are `{inf, inf}` with `errno == 0`

---

## Root Cause

`pj_isea_data::initialize()` sets up the fast-path pointer `Q->p` only for two specific orientations:

```cpp
// src/projections/isea.cpp (~line 1329)
if (Q->output == ISEA_PLANE && Q->o_az == 0.0 && Q->aperture == 3.0 && Q->resolution == 4.) {
    if (Q->o_lat == ISEA_STD_LAT && Q->o_lon == ISEA_STD_LONG)
        p = &standardISEA;
    else if (Q->o_lat == M_PI / 2.0 && Q->o_lon == 0)
        p = &polarISEA;
    else
        p = nullptr;
}
// If outer if() is false, p stays nullptr
```

The inverse function then checks `if (p)` and returns `{inf, inf}` without any error reporting when `p == nullptr`:

```cpp
// src/projections/isea.cpp (~line 1377-1390)
if (p) {
    ...
    if (p->cartesianToGeo(input, Q, result))
        return {result.lon, result.lat};
    else
        return {inf, inf};   // no errno set
} else {
    return {inf, inf};       // no errno set
}
```

---

## Proof of Concept

See `isea_SF08_poc.c`. The PoC tests forward + inverse for default and non-default configurations, printing the error code and coordinates.

### Reproduction Steps

**Step 1 — Build PROJ 9.8.1** (ASAN not required for this bug; plain build is sufficient):

```bash
wget https://download.osgeo.org/proj/proj-9.8.1.tar.gz
tar xf proj-9.8.1.tar.gz && cd proj-9.8.1
cmake -B build \
      -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ \
      -DCMAKE_INSTALL_PREFIX="$PWD/install"
cmake --build build -j$(nproc)
cmake --install build
cd ..
```

**Step 2 — Compile and run:**

```bash
clang++ -std=c++17 -g -O1 \
    -I proj-9.8.1/install/include \
    05-isea-SF08-silent-inverse-failure/isea_SF08_poc.c \
    -L proj-9.8.1/install/lib -lproj \
    -Wl,-rpath,proj-9.8.1/install/lib \
    -lm -o poc_05

PROJ_DATA=proj-9.8.1/install/share/proj ./poc_05
```

> **Note:** The bug is fully observable in plain stdout output — no sanitizer needed.
> The `*** SILENT FAILURE ***` lines appear for every non-default ISEA configuration.

### Observed Output

```
Working configurations (p != nullptr):
  [default standard] OK: fwd=(1859520,5157736), inv=(0.500000,0.300000)

Buggy configurations (p == nullptr, inverse silently returns inf):
  [+lat_0=30] *** BUG CONFIRMED: fwd=(7063834,7562862) err=0, inv=(inf,inf) err=0 (SILENT FAILURE) ***
  [+azi=45]   *** BUG CONFIRMED: fwd=(7494451,4933771) err=0, inv=(inf,inf) err=0 (SILENT FAILURE) ***
  [+aperture=4] *** BUG CONFIRMED: fwd=(...) err=0, inv=(inf,inf) err=0 (SILENT FAILURE) ***
  [+resolution=6] *** BUG CONFIRMED: fwd=(...) err=0, inv=(inf,inf) err=0 (SILENT FAILURE) ***
  ... (10 configurations total)
```

---

## Impact

Applications relying on `proj_errno()` to detect coordinate transform failures will silently produce `(inf, inf)` coordinates for any ISEA configuration other than the two hard-coded standard/polar orientations. This can corrupt geographic data pipelines without any visible error.

**Severity:** Medium — CVSS 3.1 base score **5.3** (`AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N`). No crash or availability impact, but downstream data integrity is silently compromised.  
**CWE:** [CWE-393: Return of Wrong Status Code](https://cwe.mitre.org/data/definitions/393.html)

---

## Suggested Fix

Set the projection error before returning `{inf, inf}`:

```diff
 } else {
+    pj_ctx_set_errno(P->ctx, PROJ_ERR_COORD_TRANSFM_OUTSIDE_PROJECTION_DOMAIN);
     return {inf, inf};
 }
```

Alternatively, return `{HUGE_VAL, HUGE_VAL}` using the standard mechanism (`proj_trans_error`) so PROJ's coordinate validity checks apply automatically.
