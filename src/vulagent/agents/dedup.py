#!/usr/bin/env python3
"""Deduplication agent for chat_scan hypothesis lists.

For each hypothesis in `all_hypotheses`:
  1. Ask the model whether it is a genuine security vulnerability (drop if not).
  2. Ask the model for the relevant CWE IDs.

Then deduplicate the remaining hypotheses based on overlapping line ranges
AND shared CWE IDs (union-find).

Produces a slim output file with two fields:
  - all_hypotheses: every hypothesis, with a `_removed` reason if it was dropped
  - deduped_hypotheses: surviving hypotheses after filtering and dedup

Examples:
    python -m vulagent.agents.dedup result.json -m claude-haiku-4-5-20251001
    python -m vulagent.agents.dedup result.json -m claude-haiku-4-5-20251001 \\
        --base-url https://litellm-proxy --api-key sk-... --output out.json
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

import litellm


# ---------------------------------------------------------------------------
# LLM helper
# ---------------------------------------------------------------------------


def _query(model: str, prompt: str, kwargs: dict) -> str:
    max_retries, base_delay = 6, 4.0
    import time
    for attempt in range(max_retries):
        try:
            resp = litellm.completion(
                model=model,
                messages=[{"role": "user", "content": prompt}],
                **kwargs,
            )
            return resp.choices[0].message.content or ""
        except litellm.RateLimitError:
            if attempt == max_retries - 1:
                raise
            time.sleep(base_delay * (2 ** attempt))
    raise RuntimeError("Unreachable")


# ---------------------------------------------------------------------------
# Per-hypothesis LLM checks
# ---------------------------------------------------------------------------


def _format_hypothesis(hyp: dict, source_lines: list[str] | None = None) -> str:
    h = hyp.get("hypothesis", hyp)
    parts = []
    if h.get("summary"):
        parts.append(f"Summary: {h['summary']}")
    hotspots = h.get("hotspots", [])
    if hotspots:
        for hs in hotspots:
            loc = f"{hs.get('file_path','')}:{hs.get('line_start')}-{hs.get('line_end')}"
            fn = hs.get("function", "")
            ctx = hs.get("context", "")
            header = f"Hotspot: {loc} ({fn}) — {ctx}" if fn else f"Hotspot: {loc} — {ctx}"
            parts.append(header)
            if source_lines:
                s = (hs.get("line_start") or 1) - 1
                e = hs.get("line_end") or s
                snippet = "\n".join(source_lines[s:e])
                if snippet.strip():
                    parts.append(f"```\n{snippet}\n```")
    warnings = h.get("warnings", [])
    if warnings:
        parts.append("Warnings: " + "; ".join(str(w) for w in warnings))
    return "\n".join(parts)

def classify_hypothesis(hyp: dict, model: str, kwargs: dict, source_lines: list[str] | None = None) -> dict:
    """Ask the model: is this a real vulnerability that can trigger ASAN crash? What CWE IDs apply?

    Returns dict with keys: is_vulnerability (bool), is_asan (bool), cwe_ids (list[str]),
    reason (str).
    """
    text = _format_hypothesis(hyp, source_lines)
    prompt = (
        "You are a security expert. Given the following vulnerability hypothesis, answer two questions:\n\n"
        f"{text}\n\n"
        "1. Is this a genuine security vulnerability? Answer YES or NO.\n"
        "   - Answer NO if it is speculative, informational, a best-practice issue without exploitability, "
        "or not a real security bug.\n"
        "2. Is this a security vulnerability that may potentially lead to address sanitizer crash? Answer YES or NO.\n"
        "   - Answer NO if it cannot likely crash the address sanitizer on an specially-crafted input or if it is hard to detect\n"
        "3. If YES, list the most relevant CWE IDs (e.g. CWE-476, CWE-125). List at most 3.\n\n"
        "Respond with JSON only, no prose:\n"
        '{"is_vulnerability": true|false, "is_asan": true|false, "cwe_ids": ["CWE-XXX", ...], "reason": "one sentence"}'
    )
    raw = _query(model, prompt, kwargs)
    m = re.search(r"\{[\s\S]*\}", raw)
    try:
        result = json.loads(m.group(0) if m else raw)
        return {
            "is_vulnerability": bool(result.get("is_vulnerability", False)),
            "cwe_ids": [str(c) for c in result.get("cwe_ids", [])],
            "reason": result.get("reason", ""),
        }
    except (json.JSONDecodeError, AttributeError):
        return {"is_vulnerability": False, "cwe_ids": [], "reason": f"parse error: {raw[:200]}"}


# ---------------------------------------------------------------------------
# Union-find dedup
# ---------------------------------------------------------------------------


class _UF:
    def __init__(self, n: int):
        self.parent = list(range(n))

    def find(self, x: int) -> int:
        while self.parent[x] != x:
            self.parent[x] = self.parent[self.parent[x]]
            x = self.parent[x]
        return x

    def union(self, x: int, y: int) -> None:
        self.parent[self.find(x)] = self.find(y)


def _hotspots(hyp: dict) -> list[dict]:
    return hyp.get("hypothesis", hyp).get("hotspots", [])


def _line_overlap(hs_a: list[dict], hs_b: list[dict]) -> bool:
    for a in hs_a:
        for b in hs_b:
            if a.get("file_path") != b.get("file_path"):
                continue
            s1, e1 = a.get("line_start") or 0, a.get("line_end") or 0
            s2, e2 = b.get("line_start") or 0, b.get("line_end") or 0
            if s1 <= e2 and s2 <= e1:
                return True
    return False


def dedup(hypotheses: list[dict], cwe_map: dict[int, list[str]]) -> tuple[list[dict], list[dict]]:
    """Dedup by line overlap + shared CWE ID.

    Returns (kept, removed_with_reason).
    """
    n = len(hypotheses)
    if n <= 1:
        return list(hypotheses), []

    uf = _UF(n)
    hs_cache = [_hotspots(h) for h in hypotheses]

    for i in range(n):
        for j in range(i + 1, n):
            if not _line_overlap(hs_cache[i], hs_cache[j]):
                continue
            cwes_i = set(cwe_map.get(i, []))
            cwes_j = set(cwe_map.get(j, []))
            if cwes_i & cwes_j:  # shared CWE
                uf.union(i, j)

    groups: dict[int, list[int]] = defaultdict(list)
    for i in range(n):
        groups[uf.find(i)].append(i)

    kept, removed = [], []
    for members in sorted(groups.values(), key=lambda g: g[0]):
        # Keep the member with the most hotspots; remove the rest
        best = max(members, key=lambda i: len(hs_cache[i]))
        kept.append(hypotheses[best])
        for idx in members:
            if idx != best:
                entry = dict(hypotheses[idx])
                best_summary = hypotheses[best].get("hypothesis", hypotheses[best]).get("summary", "")
                entry["_removed"] = (
                    f"Duplicate of '{best_summary[:80]}' "
                    f"(overlapping lines + shared CWEs: {sorted(set(cwe_map.get(idx,[])) & set(cwe_map.get(best,[])))})"
                )
                removed.append(entry)

    return kept, removed


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main() -> None:
    parser = argparse.ArgumentParser(description="Filter and dedup chat_scan hypotheses via LLM")
    parser.add_argument("input", help="Path to result.json")
    parser.add_argument("-m", "--model", default=os.getenv("MSWEA_MODEL_NAME"),
                        help="Model name (default: MSWEA_MODEL_NAME env var)")
    parser.add_argument("-b", "--base-url", default=None, help="LiteLLM proxy base URL")
    parser.add_argument("-k", "--api-key", default=os.getenv("MSWEA_MODEL_API_KEY"), help="API key")
    parser.add_argument("-o", "--output", default=None,
                        help="Output path (default: <input_stem>_dedup.json next to input)")
    parser.add_argument("--workers", type=int, default=16, help="Parallel LLM workers")
    args = parser.parse_args()

    input_path = Path(args.input)
    if not input_path.is_file():
        print(f"Error: not found: {input_path}", file=sys.stderr)
        sys.exit(1)

    model = args.model
    if not model:
        print("Error: no model specified. Use --model or set MSWEA_MODEL_NAME.", file=sys.stderr)
        sys.exit(1)

    model_kwargs: dict = {"temperature": 0.0, "drop_params": True}
    if args.base_url:
        model_kwargs["base_url"] = args.base_url
    if args.api_key:
        model_kwargs["api_key"] = args.api_key

    output_path = Path(args.output) if args.output else input_path.parent / f"{input_path.stem}_dedup.json"

    data = json.loads(input_path.read_text())
    hypotheses = data.get("all_hypotheses", [])
    if not hypotheses:
        print("No all_hypotheses found.", file=sys.stderr)
        sys.exit(1)

    source_lines: list[str] | None = None
    source_file = data.get("info", {}).get("file_path")
    if source_file and Path(source_file).is_file():
        source_lines = Path(source_file).read_text(errors="replace").splitlines()
        print(f"Source file: {source_file} ({len(source_lines)} lines)")
    else:
        print("Source file not found; code snippets will be omitted.", file=sys.stderr)

    print(f"Classifying {len(hypotheses)} hypotheses with {args.workers} workers...")

    # Step 1: classify each hypothesis in parallel
    classifications: dict[int, dict] = {}
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = {pool.submit(classify_hypothesis, h, model, model_kwargs, source_lines): i
                   for i, h in enumerate(hypotheses)}
        done = 0
        for future in as_completed(futures):
            idx = futures[future]
            done += 1
            try:
                classifications[idx] = future.result()
                is_vuln = classifications[idx]["is_vulnerability"]
                is_asan = classifications[idx]["is_asan"]
                print(f"  [{done}/{len(hypotheses)}] {('ASAN' if is_asan else 'VUL') if is_vuln else 'NOT'} — "
                      f"{classifications[idx]['reason'][:70]}")
            except Exception as e:
                classifications[idx] = {"is_vulnerability": False, "is_asan": False, "cwe_ids": [], "reason": f"error: {e}"}
                print(f"  [{done}/{len(hypotheses)}] ERROR: {e}", file=sys.stderr)

    # Step 2: filter out non-vulnerabilities
    valid_indices = [i for i in range(len(hypotheses)) if classifications[i]["is_vulnerability"] and classifications[i]["is_asan"] ]
    filtered_out = [i for i in range(len(hypotheses)) if not (classifications[i]["is_vulnerability"] and classifications[i]["is_asan"])]

    print(f"\nFiltered: {len(filtered_out)} non-ASan-vulnerabilities removed, {len(valid_indices)} remain")

    # Build annotated all_hypotheses list
    all_annotated = []
    for i, h in enumerate(hypotheses):
        entry = dict(h)
        entry["_cwe_ids"] = classifications[i]["cwe_ids"]
        entry["_is_vulnerability"] = classifications[i]["is_vulnerability"]
        if not classifications[i]["is_vulnerability"]:
            entry["_removed"] = f"Not a vulnerability: {classifications[i]['reason']}"
        all_annotated.append(entry)

    # Step 3: dedup valid ones by line overlap + CWE
    valid_hyps = [hypotheses[i] for i in valid_indices]
    cwe_map = {j: classifications[valid_indices[j]]["cwe_ids"] for j in range(len(valid_indices))}

    kept, removed = dedup(valid_hyps, cwe_map)

    # Annotate removed-by-dedup entries in all_annotated
    removed_summaries = {
        r.get("hypothesis", r).get("summary", ""): r.get("_removed", "")
        for r in removed
    }
    for entry in all_annotated:
        if entry.get("_is_vulnerability") and not entry.get("_removed"):
            summary = entry.get("hypothesis", entry).get("summary", "")
            if summary in removed_summaries:
                entry["_removed"] = removed_summaries[summary]

    print(f"Dedup: {len(valid_hyps)} → {len(kept)} (removed {len(valid_hyps) - len(kept)} duplicates)")

    output = {
        "all_hypotheses": all_annotated,
        "deduped_hypotheses": kept,
    }

    output_path.write_text(json.dumps(output, indent=2))
    print(f"\nSaved to: {output_path}")
    print(f"Final: {len(kept)} hypotheses")


if __name__ == "__main__":
    main()
