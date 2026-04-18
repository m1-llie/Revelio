# Stack Overflow via Unbounded Recursion in `NTv2Grid::~NTv2Grid()` Destructor

## Summary

`NTv2GridSet::open()` builds a tree of `NTv2Grid` objects where each grid's children are stored in a `std::vector<unique_ptr<HorizontalShiftGrid>>`. When a malformed NTv2 file encodes an arbitrarily deep parent-child hierarchy, the destructor chain `~NTv2Grid()` → `~HorizontalShiftGrid()` → vector destructor → `~NTv2Grid()` recurses unboundedly, causing a stack overflow.

- **Affected file:** `src/grids.cpp`
- **Affected functions:** `NTv2Grid::~NTv2Grid()` (~line 2082), `HorizontalShiftGrid::~HorizontalShiftGrid()` (~line 1752)
- **Confirmed on commit:** `324ed2119011d74665548afe445eacb99afb9753` (PROJ master, 2026-04-17)
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

```bash
docker run --rm \
  -v /path/to/bugs:/bugs \
  -v /path/to/PROJ-latest:/src/PROJ-latest:ro \
  -v /path/to/proj4-latest-build:/proj4-latest-build:ro \
  vulagent/proj4-asan:latest bash -c "
    clang++ -std=c++17 -fsanitize=address -g -O1 \
      -I/src/PROJ-latest/src -I/src/PROJ-latest/include \
      /bugs/10-grids-SF10-ntv2-destructor-overflow/grids_SF10_poc.cpp \
      /proj4-latest-build/lib/libproj.a \
      -lpthread /usr/lib/x86_64-linux-gnu/libsqlite3.so.0 -ldl -lm \
      -o /tmp/poc_10

    ASAN_OPTIONS=detect_leaks=0 PROJ_DATA=/out/asan \
      /tmp/poc_10 /bugs/10-grids-SF10-ntv2-destructor-overflow/sf10_deep.gsb
  "
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
