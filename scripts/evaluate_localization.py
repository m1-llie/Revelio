#!/usr/bin/env python3
"""
Evaluate vulnerability localization by asking GPT-4o whether any agent
hypothesis correctly identifies the true vulnerability (as revealed by
the ground-truth patch).

Supports: batch_file_scan, batch_claude_code, batch_chat_scan
"""

import argparse
import json
import os
import re
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

import yaml
import openai


# ---------------------------------------------------------------------------
# Hypothesis extraction per agent type
# ---------------------------------------------------------------------------

def _format_hypothesis(h: dict) -> str:
    """Format a structured hypothesis dict as readable text."""
    parts = []
    if h.get("summary"):
        parts.append(f"Summary: {h['summary']}")
    if h.get("harness_entry"):
        parts.append(f"Entry point: {h['harness_entry']}")
    hotspots = h.get("hotspots", [])
    if hotspots:
        hs_lines = []
        for hs in hotspots:
            fp = hs.get("file_path", "")
            fn = hs.get("function", "")
            ls, le = hs.get("line_start"), hs.get("line_end")
            ctx = hs.get("context", "")
            loc = f"{fp}:{ls}-{le}" if ls else fp
            hs_str = loc
            if fn:
                hs_str += f" ({fn})"
            if ctx:
                hs_str += f" — {ctx}"
            hs_lines.append(hs_str)
        parts.append("Hotspots:\n  " + "\n  ".join(hs_lines))
    warnings = h.get("warnings", [])
    if warnings:
        parts.append("Warnings:\n  " + "\n  ".join(str(w) for w in warnings[:3]))
    return "\n".join(parts)


def extract_file_scan_hypotheses(result_path: Path) -> str:
    """Extract hypothesis text from file_scan trajectory.json."""
    with open(result_path) as f:
        data = json.load(f)
    submission = data.get("info", {}).get("submission", "")
    if not submission:
        return ""
    try:
        parsed = yaml.safe_load(submission)
    except Exception:
        return ""
    payload_str = parsed.get("payload", "") if isinstance(parsed, dict) else ""
    if not payload_str:
        return ""
    try:
        payload = json.loads(payload_str)
    except Exception:
        return ""
    parts = []
    for i, item in enumerate(payload if isinstance(payload, list) else [payload], 1):
        h = item.get("hypothesis", {})
        parts.append(f"Hypothesis {i}:\n{_format_hypothesis(h)}")
    return "\n\n".join(parts)


def extract_claude_code_hypotheses(result_path: Path) -> str:
    """Extract hypothesis text from claude_code report.json (free-text result)."""
    with open(result_path) as f:
        data = json.load(f)
    return data.get("result", "")


def extract_chat_scan_hypotheses(result_path: Path) -> str:
    """Extract hypothesis text from chat_scan result.json['hypotheses']['hypotheses']."""
    with open(result_path) as f:
        data = json.load(f)
    hypotheses = data.get("hypotheses", {}).get("hypotheses", [])
    parts = []
    for i, h_entry in enumerate(hypotheses, 1):
        h = h_entry.get("hypothesis", {})
        if isinstance(h, dict):
            parts.append(f"Hypothesis {i}:\n{_format_hypothesis(h)}")
        else:
            parts.append(f"Hypothesis {i}: {h}")
    return "\n\n".join(parts)


# ---------------------------------------------------------------------------
# LLM evaluation
# ---------------------------------------------------------------------------

SYSTEM_PROMPT = """\
You are a security expert evaluating whether a vulnerability analysis correctly identifies a real CVE.

Given a CVE description, the ground-truth patch (what was actually fixed), and a list of hypotheses
from a security analysis tool, determine whether any hypothesis correctly identifies the true vulnerability.

Respond with JSON only:
{
  "hit": <true|false>,
  "reasoning": "<one or two sentences explaining the decision>",
  "matched_hypothesis": "<short quote or paraphrase of the matching hypothesis, or null>"
}"""


def evaluate_with_llm(
    cve_id: str,
    hypotheses_text: str,
    patch_text: str,
    cve_description: str,
    client: openai.OpenAI,
    model: str = "gpt-4o",
    max_retries: int = 3,
) -> dict:
    """Call GPT-4o to evaluate if any hypothesis identifies the true vulnerability."""
    if not hypotheses_text.strip():
        return {"hit": False, "reasoning": "No hypotheses extracted.", "matched_hypothesis": None}

    user_msg = (
        f"CVE ID: {cve_id}\n"
        f"Description: {cve_description}\n\n"
        f"Ground-truth patch:\n```diff\n{patch_text[:8000]}\n```\n\n"
        f"Agent hypotheses:\n{hypotheses_text[:6000]}\n\n"
        f"Do any of these hypotheses correctly identify the vulnerability? The hypotheses must be **strictly identifying** the EXACT SAME vulnerability. Judge by checking if the patch would fix any of the hypotheses."
    )

    for attempt in range(max_retries):
        try:
            resp = client.chat.completions.create(
                model=model,
                messages=[
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": user_msg},
                ],
                response_format={"type": "json_object"},
                temperature=0,
                max_tokens=512,
            )
            result = json.loads(resp.choices[0].message.content)
            return {
                "hit": bool(result.get("hit", False)),
                "reasoning": result.get("reasoning", ""),
                "matched_hypothesis": result.get("matched_hypothesis"),
            }
        except openai.RateLimitError:
            if attempt < max_retries - 1:
                time.sleep(2 ** attempt)
            else:
                raise
        except Exception as e:
            raise e
            return {"hit": False, "reasoning": f"LLM error: {e}", "matched_hypothesis": None}

    return {"hit": False, "reasoning": "Max retries exceeded.", "matched_hypothesis": None}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def load_dataset(dataset_path: str) -> dict:
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
    if isinstance(obj, set):
        return sorted(obj)
    raise TypeError(f"Object of type {type(obj)} is not JSON serializable")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

AGENT_CONFIGS = {
    "file_scan":   ("batch_file_scan",   "trajectory.json", extract_file_scan_hypotheses),
    "claude_code": ("batch_claude_code", "report.json",     extract_claude_code_hypotheses),
    "chat_scan":   ("batch_chat_scan",   "result.json",     extract_chat_scan_hypotheses),
}


def main():
    parser = argparse.ArgumentParser(description="Evaluate vulnerability localization via GPT-4o")
    parser.add_argument("--output-dir", default="output")
    parser.add_argument("--dataset", default="scripts/cve_dataset.jsonl")
    parser.add_argument("--patches-dir", default="scripts/patches")
    parser.add_argument("--agent", choices=[*AGENT_CONFIGS.keys(), "all"], default="all")
    parser.add_argument("--json-output", default=None)
    parser.add_argument("--workers", type=int, default=32, help="Concurrent LLM calls (default: 32)")
    parser.add_argument("--model", default="openai/gpt-4o")
    parser.add_argument("--base-url", default=None)
    parser.add_argument("--api-key", default=None,
                        help="API key")
    args = parser.parse_args()

    api_key = args.api_key
    if not api_key:
        print("ERROR: No OpenAI API key. Set OPENAI_API_KEY or pass --openai-api-key.")
        sys.exit(1)
    base_url = args.base_url
    if not base_url:
        print("ERROR: No base URL.")
        sys.exit(1)
    

    client = openai.OpenAI(api_key=api_key, base_url=base_url)
    base = Path(args.output_dir)
    dataset = load_dataset(args.dataset)

    agents_to_eval = list(AGENT_CONFIGS.keys()) if args.agent == "all" else [args.agent]
    all_results = {}

    def _eval_one(agent_key, cve_dir, result_file, extract_fn):
        """Evaluate a single CVE dir; returns (agent_key, result_dict) or None to skip."""
        cve_id = cve_dir.name
        result_path = cve_dir / result_file
        patch_path = Path(args.patches_dir) / f"{cve_id}.patch"

        if not result_path.exists():
            print(f"  SKIP {cve_id} [{agent_key}]: no {result_file}")
            return None
        if not patch_path.exists():
            print(f"  SKIP {cve_id} [{agent_key}]: no patch")
            return None
        if cve_id not in dataset:
            print(f"  SKIP {cve_id} [{agent_key}]: not in dataset")
            return None

        entry = dataset[cve_id]
        patch_text = patch_path.read_text(errors="replace")
        hypotheses_text = extract_fn(result_path)

        verdict = evaluate_with_llm(
            cve_id, hypotheses_text, patch_text,
            entry.get("description", ""), client, model=args.model,
        )

        result = {
            "cve_id": cve_id,
            "hit": verdict["hit"],
            "reasoning": verdict["reasoning"],
            "matched_hypothesis": verdict["matched_hypothesis"],
        }

        tag = "HIT " if verdict["hit"] else "MISS"
        print(f"  [{tag}] {cve_id} [{agent_key}]: {verdict['reasoning'][:80]}")

        score_path = cve_dir / "score.json"
        try:
            with open(score_path, "w") as sf:
                json.dump(result, sf, indent=2)
        except Exception as e:
            print(f"  WARNING: failed to write {score_path}: {e}")

        return agent_key, result

    # Build all tasks across all agents
    tasks = []
    for agent_key in agents_to_eval:
        dir_name, result_file, extract_fn = AGENT_CONFIGS[agent_key]
        agent_dir = base / dir_name
        if not agent_dir.exists():
            print(f"WARNING: {agent_dir} does not exist, skipping.")
            continue
        for cve_dir in sorted(d for d in agent_dir.iterdir() if d.is_dir() and re.match(r"CVE-", d.name)):
            tasks.append((agent_key, cve_dir, result_file, extract_fn))

    print(f"Evaluating {len(tasks)} runs with {args.workers} workers...")

    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = {pool.submit(_eval_one, *t): t for t in tasks}
        for fut in as_completed(futures):
            res = fut.result()
            if res is not None:
                agent_key, result = res
                all_results.setdefault(agent_key, []).append(result)

    # Print per-agent summary
    for agent_key in agents_to_eval:
        results = all_results.get(agent_key, [])
        print(f"\n{'='*60}")
        print(f"Agent: {agent_key}")
        print(f"{'='*60}")
        n = len(results)
        if n:
            hits = sum(1 for r in results if r["hit"])
            print(f"  Total: {n}   Hits: {hits}   Hit rate: {hits/n:.1%}")
            for r in sorted(results, key=lambda x: x["cve_id"]):
                tag = "HIT " if r["hit"] else "MISS"
                print(f"  [{tag}] {r['cve_id']}: {r['reasoning'][:80]}")
        else:
            print("  No results.")

    if args.json_output:
        with open(args.json_output, "w") as f:
            json.dump(all_results, f, indent=2, default=_json_serialize)
        print(f"\nResults written to {args.json_output}")


if __name__ == "__main__":
    main()
