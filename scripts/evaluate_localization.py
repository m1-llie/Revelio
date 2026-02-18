#!/usr/bin/env python3
"""
Evaluate vulnerability localization from agent reports against ground-truth patches.

Compares the files/functions/lines identified by agents (batch_file_scan, batch_claude_code)
against the actual patch files and CVE dataset ground truth.

Metrics:
  - File-level: Did the agent identify the correct file(s)?
  - Function-level: Did the agent identify the correct function(s)?
  - Line-level: Did the agent's reported line ranges overlap with patched lines?
"""

import argparse
import json
import os
import re
import sys
from collections import defaultdict
from pathlib import Path

import yaml


# ---------------------------------------------------------------------------
# Patch parsing
# ---------------------------------------------------------------------------

def parse_patch(patch_path: str) -> dict:
    """Parse a unified diff patch and extract changed files, hunks, and function context."""
    with open(patch_path) as f:
        patch = f.read()

    files = {}
    current_file = None

    for line in patch.splitlines():
        # Detect file (prefer +++ b/... for new file path)
        m = re.match(r'^--- a/(.*)', line)
        if m:
            current_file = m.group(1)
            if current_file not in files:
                files[current_file] = {"hunks": [], "changed_lines": set(), "functions": set()}
            continue

        m = re.match(r'^\+\+\+ b/(.*)', line)
        if m:
            current_file = m.group(1)
            if current_file not in files:
                files[current_file] = {"hunks": [], "changed_lines": set(), "functions": set()}
            continue

        # Parse hunk header: @@ -old_start,old_count +new_start,new_count @@ context
        m = re.match(r'^@@ -(\d+)(?:,\d+)? \+(\d+)(?:,\d+)? @@\s*(.*)', line)
        if m and current_file:
            old_start = int(m.group(1))
            new_start = int(m.group(2))
            func_context = m.group(3).strip()
            files[current_file]["hunks"].append({
                "old_start": old_start,
                "new_start": new_start,
                "func_context": func_context,
            })
            # Extract function name from context (e.g., "void foo()" -> "foo")
            if func_context:
                # Try common patterns: C/C++/Rust function signatures
                fn_match = re.search(r'(?:fn|function|def|void|int|char|bool|static|pub|unsigned|long|size_t|uint\w+|int\w+)\s+\**(\w+)\s*\(', func_context)
                if fn_match:
                    files[current_file]["functions"].add(fn_match.group(1))
                else:
                    # Try simpler: word followed by (
                    fn_match = re.search(r'(\w+)\s*\(', func_context)
                    if fn_match:
                        files[current_file]["functions"].add(fn_match.group(1))
            continue

        # Track changed lines (additions and deletions in original file)
        if current_file and files[current_file]["hunks"]:
            pass  # We track at hunk level

    # Compute changed line ranges from the patch
    current_file = None
    old_line = 0
    new_line = 0
    for line in patch.splitlines():
        m = re.match(r'^--- a/(.*)', line)
        if m:
            current_file = m.group(1)
            continue
        m = re.match(r'^\+\+\+ b/(.*)', line)
        if m:
            current_file = m.group(1)
            continue
        m = re.match(r'^@@ -(\d+)(?:,\d+)? \+(\d+)(?:,\d+)? @@', line)
        if m:
            old_line = int(m.group(1))
            new_line = int(m.group(2))
            continue
        if current_file and current_file in files:
            if line.startswith('-') and not line.startswith('---'):
                files[current_file]["changed_lines"].add(old_line)
                old_line += 1
            elif line.startswith('+') and not line.startswith('+++'):
                files[current_file]["changed_lines"].add(new_line)
                new_line += 1
            else:
                old_line += 1
                new_line += 1

    return files


# ---------------------------------------------------------------------------
# Report parsing: batch_file_scan
# ---------------------------------------------------------------------------

def parse_file_scan_report(trajectory_path: str) -> list[dict]:
    """Parse file_scan trajectory.json and extract localization from the submission payload."""
    with open(trajectory_path) as f:
        data = json.load(f)

    info = data.get("info", {})
    submission = info.get("submission", "")
    if not submission:
        return []

    # The submission is YAML-formatted
    try:
        parsed = yaml.safe_load(submission)
    except Exception:
        return []

    if not isinstance(parsed, dict):
        return []

    payload_str = parsed.get("payload")
    if not payload_str:
        return []

    try:
        payload = json.loads(payload_str)
    except Exception:
        return []

    results = []
    for item in payload:
        hyp = item.get("hypothesis", {})
        hotspots = hyp.get("hotspots", [])
        for hs in hotspots:
            results.append({
                "file": hs.get("file_path", ""),
                "line_start": hs.get("line_start"),
                "line_end": hs.get("line_end"),
                "function": hs.get("function", ""),
            })
    return results


# ---------------------------------------------------------------------------
# Report parsing: batch_claude_code
# ---------------------------------------------------------------------------

def parse_claude_code_report(report_path: str) -> list[dict]:
    """Parse claude_code report.json and extract localization from the result text.

    The claude_code reports use several patterns:
    1. file:line or file:line-line references (e.g., `entropy.rs:178`)
    2. Section headers with file paths (e.g., `# Report: /src/filter/pdftoraster.cxx`)
    3. **Location:** lines with "Lines NNN-NNN, `function()`" (file from header)
    4. Standalone "line NNN" or "lines NNN-NNN" references
    """
    with open(report_path) as f:
        data = json.load(f)

    result_text = data.get("result", "")
    if not result_text:
        return []

    results = []
    seen = set()

    def add_loc(file_path, line_start, line_end=None, function=""):
        if line_end is None:
            line_end = line_start
        key = (file_path, line_start, line_end)
        if key not in seen:
            seen.add(key)
            results.append({
                "file": file_path,
                "line_start": line_start,
                "line_end": line_end,
                "function": function,
            })

    # Step 1: Determine the primary file from the report header/title
    # Patterns: `/src/path/file.ext`, `# ... /path/file.ext`, backtick-quoted paths
    primary_file = None
    header_match = re.search(r'/src/([\w/.-]+\.\w+)', result_text)
    if header_match:
        primary_file = header_match.group(1)

    # Pattern 1: file:line or file:line-line references
    for ref in re.finditer(r'([\w/.-]+\.\w+):(\d+)(?:\s*[-–]\s*(\d+))?', result_text):
        file_path = ref.group(1)
        line_start = int(ref.group(2))
        line_end = int(ref.group(3)) if ref.group(3) else line_start
        add_loc(file_path, line_start, line_end)

    # Pattern 2: **Location:** lines with various formats for function + line
    # Covers:
    #   **Location:** `file:line` — `func()`, ...
    #   **Location:** `file`, function `name`, lines N-N
    #   **Location:** `file`, `func` (line N), ...
    #   **Location:** Lines NNN-NNN, `func()`
    for m in re.finditer(r'\*\*Location[:\*]*\s*(.+)', result_text):
        loc_line = m.group(1)

        # Extract all function names from this location line:
        # `func()`, function `name`, `Name::method`, `func` (before parens context)
        funcs_in_loc = set()
        for fm in re.finditer(r'`(\w+(?:::\w+)*)\(\)`', loc_line):
            funcs_in_loc.add(fm.group(1))
        for fm in re.finditer(r'function\s+`(\w+(?:::\w+)*)`', loc_line):
            funcs_in_loc.add(fm.group(1))
        # `file`, `funcName` (line N) — func is second backtick-quoted word
        for fm in re.finditer(r'`[\w/.-]+\.\w+`\s*,\s*`(\w+(?:::\w+)*)`', loc_line):
            funcs_in_loc.add(fm.group(1))
        # — `func()` after em-dash
        for fm in re.finditer(r'—\s*`(\w+(?:::\w+)*)\(\)`', loc_line):
            funcs_in_loc.add(fm.group(1))
        func_str = ", ".join(sorted(funcs_in_loc)) if funcs_in_loc else ""

        # Extract line numbers from this location line
        # lines ~NNN–NNN, line NNN, lines NNN-NNN, (line N)
        line_refs = re.findall(r'[Ll]ines?\s+~?(\d+)(?:\s*[-–]\s*~?(\d+))?', loc_line)
        paren_lines = re.findall(r'\(line\s+(\d+)\)', loc_line)

        file_for_loc = primary_file or ""
        # Also check if there's a file reference in this location line
        file_in_loc = re.search(r'`([\w/.-]+\.\w+)`', loc_line)
        if file_in_loc:
            candidate = file_in_loc.group(1)
            # Only use it if it looks like a real file path (has extension with code-like suffix)
            if re.match(r'.*\.(c|cpp|cxx|cc|h|hpp|rs|go|py|js|ts|sol|java|rb|mustache)\b', candidate):
                file_for_loc = candidate

        if file_for_loc:
            for lr in line_refs:
                ls = int(lr[0])
                le = int(lr[1]) if lr[1] else ls
                add_loc(file_for_loc, ls, le, func_str)
            for pl in paren_lines:
                add_loc(file_for_loc, int(pl), int(pl), func_str)

    # Pattern 3: Standalone "Lines NNN-NNN in `function()`" or "Line NNN" with function
    if primary_file:
        for m in re.finditer(
            r'[Ll]ines?\s+~?(\d+)(?:\s*[-–]\s*~?(\d+))?'
            r'(?:.*?(?:in\s+)?[`](\w+(?:::\w+)*)\(\)[`])?',
            result_text
        ):
            line_start = int(m.group(1))
            line_end = int(m.group(2)) if m.group(2) else line_start
            func = m.group(3) or ""
            add_loc(primary_file, line_start, line_end, func)

    # Pattern 4: "line NNN" standalone (with primary file)
    if primary_file:
        for m in re.finditer(r'[Ll]ine\s+(\d+)', result_text):
            line_num = int(m.group(1))
            add_loc(primary_file, line_num, line_num)

    # Pattern 5: Extract `func()` mentions anywhere in the text and associate
    # them with the primary file (as function-only locations without lines)
    if primary_file:
        for m in re.finditer(r'`(\w+(?:::\w+)*)\(\)`', result_text):
            func_name = m.group(1)
            # Only add if we don't already have this function in results
            if func_name and not any(func_name in (r.get("function") or "") for r in results):
                results.append({
                    "file": primary_file,
                    "line_start": None,
                    "line_end": None,
                    "function": func_name,
                })

    return results


# ---------------------------------------------------------------------------
# Normalization helpers
# ---------------------------------------------------------------------------

def normalize_file_path(path: str) -> str:
    """Normalize file path for comparison by stripping common prefixes."""
    # Strip leading src/, /src/, etc.
    path = path.lstrip("/")
    return path


def file_basename(path: str) -> str:
    return os.path.basename(path)


def files_match(reported: str, ground_truth: str) -> bool:
    """Check if a reported file matches the ground truth, allowing partial path matches."""
    r = normalize_file_path(reported)
    g = normalize_file_path(ground_truth)
    # Exact match
    if r == g:
        return True
    # One is suffix of the other
    if r.endswith("/" + g) or g.endswith("/" + r):
        return True
    if file_basename(r) == file_basename(g) and (r.endswith(g) or g.endswith(r)):
        return True
    # Basename + containing directory match
    if file_basename(r) == file_basename(g):
        # Check if the parent dirs overlap
        r_parts = r.split("/")
        g_parts = g.split("/")
        # Check suffix match
        min_len = min(len(r_parts), len(g_parts))
        if r_parts[-min_len:] == g_parts[-min_len:]:
            return True
    return False


def lines_overlap(reported_start, reported_end, changed_lines: set, tolerance: int = 5) -> bool:
    """Check if reported line range overlaps with changed lines (with tolerance)."""
    if not changed_lines or reported_start is None:
        return False
    if reported_end is None:
        reported_end = reported_start
    # Expand reported range by tolerance
    reported_range = set(range(reported_start - tolerance, reported_end + tolerance + 1))
    return bool(reported_range & changed_lines)


def function_matches(reported_func: str, patch_functions: set) -> bool:
    """Check if reported function name matches any patch function."""
    if not reported_func or not patch_functions:
        return False
    # Extract the base function name from e.g. "GzipBufWriter::write (Filename state)"
    # -> "write"
    parts = reported_func.split("::")
    reported_base = parts[-1].split("(")[0].split()[0].strip()

    for pf in patch_functions:
        if reported_base.lower() == pf.lower():
            return True
        if reported_base.lower() in pf.lower() or pf.lower() in reported_base.lower():
            return True
    return False


# ---------------------------------------------------------------------------
# Evaluation
# ---------------------------------------------------------------------------

def evaluate_cve(cve_id: str, reported_locs: list[dict], patch_info: dict,
                 dataset_entry: dict, tolerance: int = 5) -> dict:
    """Evaluate localization for a single CVE."""
    gt_files = [normalize_file_path(f) for f in dataset_entry.get("files", [])]
    gt_functions_changed = dataset_entry.get("functions_changed", 0)

    # Collect all ground-truth functions and changed lines across patch files
    gt_functions = set()
    gt_changed_lines = set()  # set of (norm_file, line) tuples
    for pf, pdata in patch_info.items():
        gt_functions.update(pdata["functions"])
        for ln in pdata["changed_lines"]:
            gt_changed_lines.add((normalize_file_path(pf), ln))

    result = {
        "cve_id": cve_id,
        "gt_files": gt_files,
        "gt_functions": sorted(gt_functions),
        "gt_functions_changed": gt_functions_changed,
        "gt_changed_line_count": len(gt_changed_lines),
        "num_reported_locs": len(reported_locs),
        "file_hit": False,
        "function_hit": False,
        "line_hit": False,
        "file_hit_any": False,
        "reported_files": [],
        "matched_files": [],
        "details": [],
        "file_recall": 0.0,
        "file_precision": 0.0,
        "func_recall": 0.0,
        "func_precision": 0.0,
        "line_recall": 0.0,
        "line_precision": 0.0,
    }

    if not reported_locs:
        return result

    reported_files = set()
    for loc in reported_locs:
        rf = normalize_file_path(loc["file"])
        reported_files.add(rf)
    result["reported_files"] = sorted(reported_files)

    # ---- File-level evaluation ----
    matched_gt_files = set()
    for rf in reported_files:
        for gf in gt_files:
            if files_match(rf, gf):
                matched_gt_files.add(gf)

    result["matched_files"] = sorted(matched_gt_files)
    result["file_hit"] = len(matched_gt_files) == len(gt_files) and len(gt_files) > 0
    result["file_hit_any"] = len(matched_gt_files) > 0
    result["file_recall"] = len(matched_gt_files) / len(gt_files) if gt_files else 0.0
    result["file_precision"] = len(matched_gt_files) / len(reported_files) if reported_files else 0.0

    # ---- Function-level evaluation ----
    # Collect all reported functions (base names)
    # Handle comma-separated lists and qualified names like "Foo::bar"
    reported_functions = set()
    matched_gt_funcs = set()
    for loc in reported_locs:
        func = loc.get("function", "")
        if not func:
            continue
        # Split comma-separated function lists
        for part in func.split(","):
            part = part.strip()
            if not part:
                continue
            # Handle qualified names: take last segment
            segments = part.split("::")
            base = segments[-1].split("(")[0].split()[0].strip()
            if base:
                reported_functions.add(base)

    # Match reported functions against GT functions
    for rf in reported_functions:
        for gf in gt_functions:
            if rf.lower() == gf.lower():
                matched_gt_funcs.add(gf)
            elif rf.lower() in gf.lower() or gf.lower() in rf.lower():
                matched_gt_funcs.add(gf)

    # Count how many reported functions matched at least one GT function
    reported_funcs_that_matched = set()
    for rf in reported_functions:
        for gf in gt_functions:
            if rf.lower() == gf.lower() or rf.lower() in gf.lower() or gf.lower() in rf.lower():
                reported_funcs_that_matched.add(rf)
                break

    result["function_hit"] = len(matched_gt_funcs) > 0
    result["func_recall"] = len(matched_gt_funcs) / len(gt_functions) if gt_functions else 0.0
    result["func_precision"] = len(reported_funcs_that_matched) / len(reported_functions) if reported_functions else 0.0

    # ---- Line-level evaluation ----
    # Build the set of all reported lines (file, line) and check overlap
    reported_lines = set()  # (norm_file, line) tuples
    for loc in reported_locs:
        rf = normalize_file_path(loc["file"])
        ls = loc.get("line_start")
        le = loc.get("line_end")
        if ls is None:
            continue
        if le is None:
            le = ls
        for ln in range(ls, le + 1):
            reported_lines.add((rf, ln))

    # For recall: how many GT changed lines are covered by reported lines (with tolerance)?
    gt_lines_covered = set()
    for (gf, gln) in gt_changed_lines:
        for tol in range(-tolerance, tolerance + 1):
            # Check if any reported line in a matching file is within tolerance
            for (rf, rln) in reported_lines:
                if files_match(rf, gf) and rln == gln + tol:
                    gt_lines_covered.add((gf, gln))
                    break
            if (gf, gln) in gt_lines_covered:
                break

    # For precision: how many reported lines are near a GT changed line?
    reported_lines_matched = set()
    for (rf, rln) in reported_lines:
        for (gf, gln) in gt_changed_lines:
            if files_match(rf, gf) and abs(rln - gln) <= tolerance:
                reported_lines_matched.add((rf, rln))
                break

    result["line_hit"] = len(gt_lines_covered) > 0
    result["line_recall"] = len(gt_lines_covered) / len(gt_changed_lines) if gt_changed_lines else 0.0
    result["line_precision"] = len(reported_lines_matched) / len(reported_lines) if reported_lines else 0.0

    # ---- Per-location details ----
    for loc in reported_locs:
        rf = normalize_file_path(loc["file"])
        detail = {"reported_file": rf, "line_start": loc.get("line_start"),
                   "line_end": loc.get("line_end"), "function": loc.get("function", "")}

        for pf, pdata in patch_info.items():
            if files_match(rf, pf):
                detail["file_match"] = True
                if loc.get("line_start") is not None:
                    detail["line_overlap"] = lines_overlap(
                        loc["line_start"], loc.get("line_end"),
                        pdata["changed_lines"], tolerance)
                if loc.get("function"):
                    detail["function_match"] = function_matches(loc["function"], pdata["functions"])
                break

        result["details"].append(detail)

    return result


def load_dataset(dataset_path: str) -> dict:
    """Load CVE dataset as dict keyed by cve_id."""
    dataset = {}
    with open(dataset_path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            d = json.loads(line)
            dataset[d["cve_id"]] = d
    return dataset


def _json_serialize(obj):
    """JSON serializer for sets and other non-standard types."""
    if isinstance(obj, set):
        return sorted(obj)
    raise TypeError(f"Object of type {type(obj)} is not JSON serializable")


def main():
    parser = argparse.ArgumentParser(description="Evaluate vulnerability localization")
    parser.add_argument("--output-dir", default="output",
                        help="Path to output/ directory")
    parser.add_argument("--dataset", default="scripts/cve_dataset.jsonl",
                        help="Path to CVE dataset JSONL")
    parser.add_argument("--patches-dir", default="scripts/patches",
                        help="Path to patches directory")
    parser.add_argument("--agent", choices=["file_scan", "claude_code", "both"],
                        default="both", help="Which agent(s) to evaluate")
    parser.add_argument("--json-output", default=None,
                        help="Write detailed JSON results to file")
    parser.add_argument("--tolerance", type=int, default=5,
                        help="Line tolerance for overlap check (default: 5)")
    args = parser.parse_args()

    base = Path(args.output_dir)
    dataset = load_dataset(args.dataset)

    agents_to_eval = []
    if args.agent in ("file_scan", "both"):
        agents_to_eval.append("batch_file_scan")
    if args.agent in ("claude_code", "both"):
        agents_to_eval.append("batch_claude_code")

    all_results = {}

    for agent_name in agents_to_eval:
        agent_dir = base / agent_name
        if not agent_dir.exists():
            print(f"WARNING: {agent_dir} does not exist, skipping.")
            continue

        cve_dirs = sorted([
            d for d in agent_dir.iterdir()
            if d.is_dir() and d.name.startswith("CVE")
        ])

        results = []
        for cve_dir in cve_dirs:
            cve_id = cve_dir.name
            patch_path = Path(args.patches_dir) / f"{cve_id}.patch"

            # Try trajectory.json first (unified structured format),
            # fall back to report.json (legacy free-text format)
            traj_path = cve_dir / "trajectory.json"
            report_path = cve_dir / "report.json"
            if traj_path.exists():
                report_file_used = "trajectory.json"
                parse_fn = parse_file_scan_report
                report_path = traj_path
            elif report_path.exists():
                report_file_used = "report.json"
                parse_fn = parse_claude_code_report
            else:
                print(f"  SKIP {cve_id}: no trajectory.json or report.json")
                continue
            if not patch_path.exists():
                print(f"  SKIP {cve_id}: no patch")
                continue
            if cve_id not in dataset:
                print(f"  SKIP {cve_id}: not in dataset")
                continue

            # Parse report; if structured parse yields nothing, try free-text fallback
            reported_locs = parse_fn(str(report_path))
            if not reported_locs and parse_fn is parse_file_scan_report:
                fallback_report = cve_dir / "report.json"
                if fallback_report.exists():
                    reported_locs = parse_claude_code_report(str(fallback_report))

            # Parse patch
            patch_info = parse_patch(str(patch_path))

            # Evaluate
            result = evaluate_cve(cve_id, reported_locs, patch_info, dataset[cve_id],
                                  tolerance=args.tolerance)
            results.append(result)

            # Write score.json into the run directory
            score_path = cve_dir / "score.json"
            try:
                with open(score_path, "w") as sf:
                    json.dump(result, sf, indent=2, default=_json_serialize)
            except Exception as e:
                print(f"  WARNING: failed to write {score_path}: {e}")

        all_results[agent_name] = results

        # Print summary
        print(f"\n{'='*70}")
        print(f"Agent: {agent_name}")
        print(f"{'='*70}")
        n = len(results)
        if n == 0:
            print("  No results to evaluate.")
            continue

        file_hits = sum(1 for r in results if r["file_hit_any"])
        file_all_hits = sum(1 for r in results if r["file_hit"])
        line_hits = sum(1 for r in results if r["line_hit"])
        func_hits = sum(1 for r in results if r["function_hit"])

        avg_file_recall = sum(r["file_recall"] for r in results) / n
        avg_file_precision = sum(r["file_precision"] for r in results) / n

        avg_line_recall = sum(r["line_recall"] for r in results) / n
        avg_line_precision = sum(r["line_precision"] for r in results) / n
        # Only average over CVEs where GT has functions (avoid diluting with 0/0 cases)
        func_eval = [r for r in results if r["gt_functions"]]
        avg_func_recall = (sum(r["func_recall"] for r in func_eval) / len(func_eval)) if func_eval else 0.0
        # Only average precision over CVEs that reported at least one function
        func_reported = [r for r in results if r["func_precision"] > 0 or any(
            d.get("function") for d in r["details"])]
        avg_func_precision = (sum(r["func_precision"] for r in func_reported) / len(func_reported)) if func_reported else 0.0

        print(f"  Total CVEs evaluated: {n}")
        print(f"  Line tolerance:       ±{args.tolerance} lines")
        print()
        print(f"  {'Metric':<36} {'Hit Rate':>14}  {'Avg Recall':>11}  {'Avg Precision':>14}")
        print(f"  {'-'*36} {'-'*14}  {'-'*11}  {'-'*14}")
        print(f"  {'File-level (any GT file hit)':<36} {file_hits:>3}/{n:<3} = {file_hits/n:>5.1%}  "
              f"{avg_file_recall:>10.1%}  {avg_file_precision:>13.1%}")
        print(f"  {'File-level (all GT files hit)':<36} {file_all_hits:>3}/{n:<3} = {file_all_hits/n:>5.1%}  "
              f"{'':>11}  {'':>14}")
        print(f"  {'Function-level':<36} {func_hits:>3}/{n:<3} = {func_hits/n:>5.1%}  "
              f"{avg_func_recall:>10.1%}  {avg_func_precision:>13.1%}"
              f"  (over {len(func_eval)}/{n} with GT funcs)")
        print(f"  {'Line-level (any overlap)':<36} {line_hits:>3}/{n:<3} = {line_hits/n:>5.1%}  "
              f"{avg_line_recall:>10.1%}  {avg_line_precision:>13.1%}")

        # Per-CVE details
        print(f"\n  {'CVE ID':<20} {'#Loc':>4} "
              f"{'F.Re':>5} {'F.Pr':>5} "
              f"{'Fn.Re':>5} {'Fn.Pr':>5} "
              f"{'L.Re':>5} {'L.Pr':>5} "
              f" GT Files")
        print(f"  {'-'*20} {'-'*4} "
              f"{'-'*5} {'-'*5} "
              f"{'-'*5} {'-'*5} "
              f"{'-'*5} {'-'*5} "
              f" {'-'*30}")
        for r in results:
            fr = f"{r['file_recall']:.0%}" if r['file_recall'] > 0 else "0%"
            fp = f"{r['file_precision']:.0%}" if r['file_precision'] > 0 else "0%"
            fnr = f"{r['func_recall']:.0%}" if r['gt_functions'] else "n/a"
            fnp = f"{r['func_precision']:.0%}" if any(
                d.get("function") for d in r["details"]) else "n/a"
            lr = f"{r['line_recall']:.0%}" if r['gt_changed_line_count'] > 0 else "n/a"
            lp = f"{r['line_precision']:.0%}" if r['num_reported_locs'] > 0 else "n/a"
            gt = ", ".join(os.path.basename(f) for f in r["gt_files"])
            print(f"  {r['cve_id']:<20} {r['num_reported_locs']:>4} "
                  f"{fr:>5} {fp:>5} "
                  f"{fnr:>5} {fnp:>5} "
                  f"{lr:>5} {lp:>5} "
                  f" {gt}")

    # Write JSON output
    if args.json_output:
        with open(args.json_output, "w") as f:
            json.dump(all_results, f, indent=2, default=_json_serialize)
        print(f"\nDetailed results written to {args.json_output}")


if __name__ == "__main__":
    main()
