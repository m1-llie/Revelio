#!/usr/bin/env python3
"""Run a PoC file (or all PoCs) in the corresponding vulagent/ Docker container
and report whether a crash occurred.

Usage:
    # Single PoC
    python run_poc.py poc_craft/gpac/poc1_stts_overflow.mp4

    # Override fuzzer
    python run_poc.py poc_craft/gpac/poc1_stts_overflow.mp4 --fuzzer fuzz_parse

    # Override image
    python run_poc.py poc_craft/gpac/poc1_stts_overflow.mp4 --image vulagent/gpac:latest

    # All PoCs in a project directory
    python run_poc.py poc_craft/gpac/

    # All PoCs across all projects
    python run_poc.py poc_craft/

    # Parallel execution (default: 4 workers)
    python run_poc.py poc_craft/ --parallel 8

    # List available fuzzers for a project
    python run_poc.py --list-fuzzers gpac
"""

import argparse
import os
import subprocess
import sys
import re
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

# ── Fuzzer selection heuristics ──────────────────────────────────────────────
# Maps (project, extension) → preferred fuzzer.  Falls back to first available.
FUZZER_MAP = {
    # assimp
    ("assimp", ".fbx"):  "assimp_fuzzer_fbx",
    ("assimp", ".dae"):  "assimp_fuzzer_collada",
    ("assimp", ".obj"):  "assimp_fuzzer_obj",
    ("assimp", ".stl"):  "assimp_fuzzer_stl",
    ("assimp", ".glb"):  "assimp_fuzzer_glb",
    ("assimp", ".gltf"): "assimp_fuzzer_gltf",
    ("assimp", ".mdl"):  "assimp_fuzzer",
    # gpac
    ("gpac", ".mp4"):  "fuzz_probe_analyze",
    ("gpac", ".mpd"):  "fuzz_probe_analyze",
    ("gpac", ".xml"):  "fuzz_probe_analyze",
    ("gpac", ".ivf"):  "fuzz_probe_analyze",
    ("gpac", ".obu"):  "fuzz_probe_analyze",
    ("gpac", ".ogg"):  "fuzz_probe_analyze",
    ("gpac", ".ts"):   "fuzz_m2ts_probe",
    ("gpac", ".flv"):  "fuzz_probe_analyze",
    ("gpac", ".webm"): "fuzz_probe_analyze",
    ("gpac", ".m4v"):  "fuzz_probe_analyze",
    # libtorrent
    ("libtorrent", ".ben"):     "bdecode_node",
    ("libtorrent", ".torrent"): "torrent_info",
}

CRASH_PATTERN = re.compile(
    r"AddressSanitizer|MemorySanitizer|UndefinedBehaviorSanitizer|"
    r"LeakSanitizer|"
    r"ERROR.*[AMU]SAN|"
    r"heap-buffer-overflow|stack-buffer-overflow|"
    r"use-after-free|heap-use-after-free|"
    r"global-buffer-overflow|stack-overflow|"
    r"alloc-dealloc-mismatch|double-free|"
    r"SEGV|ABRT|FPE|BUS",
    re.IGNORECASE,
)

SUMMARY_PATTERN = re.compile(r"SUMMARY|ERROR|SCARINESS", re.IGNORECASE)


def infer_project(poc_path: Path) -> str:
    """Infer project name from path like .../poc_craft/<project>/pocN_foo.ext"""
    # Walk up to find the poc_craft parent
    parts = poc_path.resolve().parts
    for i, part in enumerate(parts):
        if part == "poc_craft" and i + 1 < len(parts):
            return parts[i + 1]
    # Fallback: immediate parent directory
    return poc_path.resolve().parent.name


def infer_fuzzer(project: str, poc_path: Path) -> str:
    ext = poc_path.suffix.lower()
    key = (project, ext)
    if key in FUZZER_MAP:
        return FUZZER_MAP[key]
    # Fallback: try to pick from filename hints
    name = poc_path.stem.lower()
    if "resume" in name:
        return "resume_data"
    if "dht" in name:
        return "dht_node"
    if "http" in name:
        return "http_parser"
    return ""


def list_fuzzers(image: str) -> list[str]:
    result = subprocess.run(
        ["docker", "run", "--rm", image, "arvo", "list"],
        capture_output=True, text=True, timeout=30,
    )
    fuzzers = []
    for line in result.stdout.splitlines():
        line = line.strip()
        if line and not line.startswith("Available"):
            fuzzers.append(line)
    return fuzzers


def run_poc(poc_path: Path, image: str, fuzzer: str, timeout: int = 30) -> dict:
    """Run a single PoC and return result dict."""
    poc_path = poc_path.resolve()
    cmd = [
        "docker", "run", "--rm",
        "-v", f"{poc_path}:/tmp/poc:ro",
        image,
        "timeout", str(timeout), "arvo", "run", fuzzer,
    ]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 15)
        output = proc.stdout + proc.stderr
        rc = proc.returncode
    except subprocess.TimeoutExpired:
        return {
            "poc": str(poc_path),
            "fuzzer": fuzzer,
            "image": image,
            "crash": False,
            "timeout": True,
            "rc": -1,
            "summary": "Timed out (host-side)",
            "output": "",
        }

    crash = bool(CRASH_PATTERN.search(output))
    summary_lines = [l for l in output.splitlines() if SUMMARY_PATTERN.search(l)]

    return {
        "poc": str(poc_path),
        "fuzzer": fuzzer,
        "image": image,
        "crash": crash,
        "timeout": False,
        "rc": rc,
        "summary": "\n".join(summary_lines[:3]) if summary_lines else "",
        "output": output,
    }


def collect_pocs(target: Path) -> list[Path]:
    """Given a file or directory, return list of PoC files."""
    if target.is_file():
        return [target]
    pocs = []
    for f in sorted(target.rglob("*")):
        if f.is_file() and not f.name.startswith(".") and f.suffix:
            # Skip scripts and non-PoC files
            if f.suffix in (".py", ".sh", ".md", ".txt", ".json"):
                continue
            pocs.append(f)
    return pocs


def print_result(r: dict, verbose: bool = False):
    name = Path(r["poc"]).name
    if r["timeout"]:
        status = "\033[33mTIMEOUT\033[0m"
    elif r["crash"]:
        status = "\033[31mCRASH\033[0m"
    else:
        status = "\033[32mNO CRASH\033[0m"

    print(f"  [{status}] {name}  (fuzzer={r['fuzzer']}, exit={r['rc']})")
    if r["summary"]:
        for line in r["summary"].split("\n"):
            print(f"         {line.strip()}")
    if verbose and r["crash"]:
        print("  --- full output ---")
        print(r["output"])
        print("  -------------------")


def main():
    parser = argparse.ArgumentParser(description="Run PoC files in vulagent Docker containers")
    parser.add_argument("target", nargs="?", help="PoC file or directory")
    parser.add_argument("--fuzzer", "-f", help="Override fuzzer binary name")
    parser.add_argument("--image", "-i", help="Override Docker image (e.g. vulagent/gpac:latest)")
    parser.add_argument("--timeout", "-t", type=int, default=30, help="Timeout in seconds (default: 30)")
    parser.add_argument("--parallel", "-p", type=int, default=4, help="Max parallel containers (default: 4)")
    parser.add_argument("--verbose", "-v", action="store_true", help="Show full output for crashes")
    parser.add_argument("--list-fuzzers", metavar="PROJECT", help="List fuzzers for a project and exit")
    args = parser.parse_args()

    if args.list_fuzzers:
        image = f"vulagent/{args.list_fuzzers}:latest"
        print(f"Fuzzers in {image}:")
        for f in list_fuzzers(image):
            print(f"  {f}")
        return

    if not args.target:
        parser.print_help()
        sys.exit(1)

    target = Path(args.target)
    if not target.exists():
        print(f"Error: {target} does not exist", file=sys.stderr)
        sys.exit(1)

    pocs = collect_pocs(target)
    if not pocs:
        print(f"No PoC files found in {target}", file=sys.stderr)
        sys.exit(1)

    print(f"Found {len(pocs)} PoC(s) to test\n")

    crashes = 0
    total = 0

    # Group by project for display
    by_project: dict[str, list[Path]] = {}
    for p in pocs:
        proj = infer_project(p)
        by_project.setdefault(proj, []).append(p)

    # Cache fuzzer lists per image to avoid repeated docker calls
    fuzzer_cache: dict[str, list[str]] = {}

    for project, project_pocs in sorted(by_project.items()):
        image = args.image or f"vulagent/{project}:latest"
        print(f"{'=' * 50}")
        print(f"  {project.upper()}  ({image}, {len(project_pocs)} PoCs)")
        print(f"{'=' * 50}")

        def _run(poc, _project=project, _image=image):
            fuzzer = args.fuzzer or infer_fuzzer(_project, poc)
            if fuzzer:
                return [run_poc(poc, _image, fuzzer, args.timeout)]
            # No fuzzer inferred — run all available fuzzers
            if _image not in fuzzer_cache:
                fuzzer_cache[_image] = list_fuzzers(_image)
            all_fuzzers = fuzzer_cache[_image]
            if not all_fuzzers:
                return [{
                    "poc": str(poc), "fuzzer": "???", "image": _image,
                    "crash": False, "timeout": False, "rc": -1,
                    "summary": "No fuzzers found in image", "output": "",
                }]
            return [run_poc(poc, _image, f, args.timeout) for f in all_fuzzers]

        with ThreadPoolExecutor(max_workers=args.parallel) as pool:
            futures = {pool.submit(_run, poc): poc for poc in project_pocs}
            results = []
            for fut in as_completed(futures):
                for r in fut.result():
                    results.append((futures[fut], r))

        # Print in original order
        results.sort(key=lambda x: (str(x[0]), x[1]["fuzzer"]))
        for _, r in results:
            print_result(r, args.verbose)
            total += 1
            if r["crash"]:
                crashes += 1
        print()

    print(f"{'=' * 50}")
    print(f"  Total: {total}  |  Crashes: {crashes}  |  Clean: {total - crashes}")
    print(f"{'=' * 50}")

    sys.exit(0 if crashes == 0 else 1)


if __name__ == "__main__":
    main()
