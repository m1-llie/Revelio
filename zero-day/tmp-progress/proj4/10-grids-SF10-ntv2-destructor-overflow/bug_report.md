# Stack Overflow via Unbounded Recursion in `NTv2Grid::~NTv2Grid()` Destructor

## Summary

`NTv2GridSet::open()` builds a tree of `NTv2Grid` objects where each grid's children are stored in a `std::vector<unique_ptr<HorizontalShiftGrid>>`. When a malformed NTv2 file encodes an arbitrarily deep parent-child hierarchy, the destructor chain `~NTv2Grid()` → `~HorizontalShiftGrid()` → vector destructor → `~NTv2Grid()` recurses unboundedly, causing a stack overflow.

- **Affected file:** `src/grids.cpp`
- **Affected functions:** `NTv2Grid::~NTv2Grid()` (~line 2082), `HorizontalShiftGrid::~HorizontalShiftGrid()` (~line 1752)
- **Confirmed on commit:** `324ed2119011d74665548afe445eacb99afb9753` (PROJ master, 2026-04-17); latest affected release: PROJ **9.8.1** (2026-04-10)
- **Sanitizer required:** AddressSanitizer (ASAN)
- **Impact:** Denial of service — process crash (stack overflow via crafted NTv2 file)

---

## Vulnerable Code

```cpp
// src/grids.cpp:~2183 — NTv2GridSet::open() builds unbounded tree:
auto iter = mapGrids.find(parentName);
if (iter == mapGrids.end()) {
    set->m_grids.emplace_back(std::move(grid));
} else {
    iter->second->m_children.emplace_back(std::move(grid));  // unbounded depth
}

// ~NTv2Grid() destroys m_children, which triggers ~NTv2Grid() for each child.
// With 10000 parent-child levels, this recurses 10000 times, exhausting the stack.
```

---

## Proof of Concept

Two files are provided:

| File | Purpose |
|------|---------|
| `grids_SF10_poc_gen.py` | Generates a malformed NTv2 `.gsb` file with a deep parent-child chain |
| `grids_SF10_poc.cpp` | Loads the malformed grid file and triggers the crash |
| `sf10_deep.gsb` | Pre-generated 10 000-level deep NTv2 file |

### Reproduction Steps

**Step 1 — Build PROJ 9.8.1 with AddressSanitizer** (one-time):

```bash
wget https://download.osgeo.org/proj/proj-9.8.1.tar.gz
tar xf proj-9.8.1.tar.gz && cd proj-9.8.1
cmake -B build \
      -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ \
      -DCMAKE_C_FLAGS="-fsanitize=address -g -O1" \
      -DCMAKE_CXX_FLAGS="-fsanitize=address -g -O1" \
      -DCMAKE_EXE_LINKER_FLAGS="-fsanitize=address" \
      -DCMAKE_SHARED_LINKER_FLAGS="-fsanitize=address" \
      -DCMAKE_INSTALL_PREFIX="$PWD/install"
cmake --build build -j$(nproc)
cmake --install build
cd ..
```

**Step 2 — Compile and run** (the pre-generated `sf10_deep.gsb` is in this folder):

```bash
clang++ -std=c++17 -fsanitize=address -g -O1 \
    -I proj-9.8.1/install/include \
    10-grids-SF10-ntv2-destructor-overflow/grids_SF10_poc.cpp \
    -L proj-9.8.1/install/lib -lproj \
    -Wl,-rpath,proj-9.8.1/install/lib \
    -o poc_10

ASAN_OPTIONS=detect_leaks=0 \
PROJ_DATA=proj-9.8.1/install/share/proj \
./poc_10 10-grids-SF10-ntv2-destructor-overflow/sf10_deep.gsb
```

The `sf10_deep.gsb` test file is a 10 000-level deep malformed NTv2 grid included with
this report. To regenerate it at a different depth, use `grids_SF10_poc_gen.py`:

```bash
python3 10-grids-SF10-ntv2-destructor-overflow/grids_SF10_poc_gen.py 10000 sf10_deep.gsb
```

### Observed Output

```
...
    #2449 in osgeo::proj::NTv2Grid::~NTv2Grid()  grids.cpp:2082:7
    #2450 in osgeo::proj::NTv2Grid::~NTv2Grid()  grids.cpp:2082:7
    ...
SUMMARY: AddressSanitizer: stack-overflow  grids.cpp:2082 in osgeo::proj::NTv2Grid::~NTv2Grid()
```

---

## Impact

Any application that loads NTv2 grid files from untrusted sources (e.g., user-supplied grid shift files) can be crashed by providing a malformed file with a deep parent-child hierarchy. The crash occurs during cleanup (on scope exit or explicit destruction).

**Severity:** Medium — CVSS 3.1 base score **6.5** (`AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H`). Rises to **7.5 High** (`UI:N`) if NTv2 files are processed automatically without user interaction (e.g., server-side geographic pipelines).  
**CWE:** [CWE-674: Uncontrolled Recursion](https://cwe.mitre.org/data/definitions/674.html), [CWE-400: Uncontrolled Resource Consumption](https://cwe.mitre.org/data/definitions/400.html)

---

## Suggested Fix

Convert the recursive destructor to an iterative approach. Before destroying children, move them to a queue and process them one level at a time:

```cpp
~NTv2Grid() noexcept override {
    // Iterative teardown to avoid stack overflow on deep hierarchies
    std::vector<std::unique_ptr<HorizontalShiftGrid>> queue;
    for (auto &c : m_children) queue.push_back(std::move(c));
    m_children.clear();
    while (!queue.empty()) {
        auto child = std::move(queue.back()); queue.pop_back();
        for (auto &gc : child->m_children) queue.push_back(std::move(gc));
        child->m_children.clear();
    }
}
```

Alternatively, cap the depth during `NTv2GridSet::open()` and reject files exceeding a safe limit.
