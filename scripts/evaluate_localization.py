#!/usr/bin/env python3
"""
Evaluate vulnerability localization by asking GPT-4o whether any agent
hypothesis correctly identifies the true vulnerability (as revealed by
the ground-truth patch).

Supports: batch_file_scan, batch_claude_code, batch_chat_scan, batch_dedup
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

def _format_hypothesis_with_code(h: dict, source_lines: list[str] | None) -> str:
    """Format a hypothesis dict, embedding numbered source lines for each hotspot."""
    parts = []
    if h.get("summary"):
        parts.append(f"Summary: {h['summary']}")
    if h.get("harness_entry"):
        parts.append(f"Entry point: {h['harness_entry']}")
    hotspots = h.get("hotspots", [])
    for hs in hotspots:
        fp = hs.get("file_path", "")
        fn = hs.get("function", "")
        ls, le = hs.get("line_start"), hs.get("line_end")
        ctx = hs.get("context", "")
        loc = f"{fp}:{ls}-{le}" if ls else fp
        header = f"Hotspot: {loc}"
        if fn:
            header += f" ({fn})"
        if ctx:
            header += f" — {ctx}"
        parts.append(header)
        if source_lines and ls and le:
            snippet_lines = source_lines[ls - 1 : le]
            numbered = "\n".join(f"{ls + i:>6}  {line}" for i, line in enumerate(snippet_lines))
            parts.append(f"```\n{numbered}\n```")
    warnings = h.get("warnings", [])
    if warnings:
        parts.append("Warnings:\n  " + "\n  ".join(str(w) for w in warnings[:3]))
    return "\n".join(parts)


def _load_source_lines(result_path: Path) -> list[str] | None:
    """Try to read source lines from the file referenced in result_path's JSON."""
    try:
        data = json.loads(result_path.read_text())
        info = data.get("info", {})
        # batch_chat_scan: info.file_path
        fp = info.get("file_path")
        if not fp:
            # batch_file_scan: info.folder_path + info.target_file
            folder = info.get("folder_path", "")
            target = info.get("target_file", "")
            fp = str(Path(folder) / target) if folder and target else None
        if fp and Path(fp).is_file():
            return Path(fp).read_text(errors="replace").splitlines()
    except Exception:
        pass
    return None


def extract_file_scan_hypotheses(result_path: Path) -> list[dict]:
    """Extract hypotheses from file_scan trajectory.json."""
    with open(result_path) as f:
        data = json.load(f)
    submission = data.get("info", {}).get("submission", "")
    if not submission:
        return []
    try:
        parsed = yaml.safe_load(submission)
    except Exception:
        return []
    payload_str = parsed.get("payload", "") if isinstance(parsed, dict) else ""
    if not payload_str:
        return []
    try:
        payload = json.loads(payload_str)
    except Exception:
        return []
    return [item.get("hypothesis", {}) for item in (payload if isinstance(payload, list) else [payload])]


def extract_claude_code_hypotheses(result_path: Path) -> list[dict]:
    """Extract free-text result from claude_code report.json as a single hypothesis."""
    with open(result_path) as f:
        data = json.load(f)
    text = data.get("result", "")
    return [{"summary": text}] if text else []


def extract_chat_scan_hypotheses(result_path: Path) -> list[dict]:
    """Extract hypotheses from chat_scan result.json (all_hypotheses + focused_analyses)."""
    with open(result_path) as f:
        data = json.load(f)
    all_hyps = data.get("all_hypotheses", [])
    seen = {e.get("hypothesis", {}).get("summary", "") for e in all_hyps if isinstance(e.get("hypothesis"), dict)}
    result = [e.get("hypothesis", e) if isinstance(e, dict) else e for e in all_hyps]
    for fa in data.get("focused_analyses", []):
        for h_entry in fa.get("hypotheses", []):
            h = h_entry.get("hypothesis", h_entry) if isinstance(h_entry, dict) else {}
            if isinstance(h, dict) and h.get("summary", "") not in seen:
                seen.add(h.get("summary", ""))
                result.append(h)
    return result


# ---------------------------------------------------------------------------
# LLM evaluation
# ---------------------------------------------------------------------------

SYSTEM_PROMPT = """\
You are a security expert evaluating whether a single vulnerability hypothesis correctly identifies a real CVE.

Given a CVE description, the ground-truth patch (what was actually fixed), and one hypothesis from a security
analysis tool (including the relevant source code lines), determine whether the hypothesis correctly identifies
the true vulnerability.

The hypothesis must be **strictly identifying** the EXACT SAME vulnerability — judge by checking if the patch
would fix this hypothesis.

Respond with JSON only:
{
  "hit": <true|false>,
  "reasoning": "<one or two sentences explaining the decision>"
}"""


def _call_llm_once(
    cve_id: str,
    hypothesis_text: str,
    patch_text: str,
    cve_description: str,
    client: openai.OpenAI,
    model: str,
    max_retries: int,
) -> dict:
    """Single LLM call for one hypothesis."""
    user_msg = (
        f"CVE ID: {cve_id}\n"
        f"Description: {cve_description}\n\n"
        f"Ground-truth patch:\n```diff\n{patch_text[:6000]}\n```\n\n"
        f"Hypothesis:\n{hypothesis_text}\n\n"
        "Does this hypothesis correctly identify the vulnerability?"
    )
    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": user_msg},
    ]
    for attempt in range(max_retries):
        try:
            resp = client.chat.completions.create(
                model=model,
                messages=messages,
                response_format={"type": "json_object"},
                temperature=0,
                max_tokens=256,
            )
            assistant_reply = resp.choices[0].message.content
            result = json.loads(assistant_reply)
            return {
                "hit": bool(result.get("hit", False)),
                "reasoning": result.get("reasoning", ""),
                "conversation": messages + [{"role": "assistant", "content": assistant_reply}],
            }
        except openai.RateLimitError:
            if attempt < max_retries - 1:
                time.sleep(2 ** attempt)
            else:
                raise
        except Exception as e:
            raise e
    return {"hit": False, "reasoning": "Max retries exceeded.", "conversation": messages}


def evaluate_with_llm(
    cve_id: str,
    hypotheses: list[dict],
    source_lines: list[str] | None,
    patch_text: str,
    cve_description: str,
    client: openai.OpenAI,
    model: str = "gpt-4o",
    max_retries: int = 3,
) -> dict:
    """Evaluate each hypothesis individually. Short-circuits on first hit."""
    if not hypotheses:
        return {"hit": False, "reasoning": "No hypotheses extracted.", "matched_hypothesis": None, "conversation": []}

    all_conversations = []
    for hyp in hypotheses:
        h = hyp if isinstance(hyp, dict) else {"summary": str(hyp)}
        text = _format_hypothesis_with_code(h, source_lines)
        result = _call_llm_once(cve_id, text, patch_text, cve_description, client, model, max_retries)
        all_conversations.append(result["conversation"])
        if result["hit"]:
            return {
                "hit": True,
                "reasoning": result["reasoning"],
                "matched_hypothesis": h.get("summary", text[:120]),
                "conversation": all_conversations,
            }

    return {
        "hit": False,
        "reasoning": f"No hypothesis matched across {len(hypotheses)} individual check(s).",
        "matched_hypothesis": None,
        "conversation": all_conversations,
    }


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



# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

AGENT_CONFIGS = {
    "file_scan":   ("batch_file_scan",   "trajectory.json", extract_file_scan_hypotheses),
    "claude_code": ("batch_claude_code", "report.json",     extract_claude_code_hypotheses),
    "chat_scan":   ("batch_chat_scan",   "result.json",     extract_chat_scan_hypotheses),
}

ALL_AGENTS = list(AGENT_CONFIGS.keys()) + ["batch_dedup"]


# ---------------------------------------------------------------------------
# Dedup evaluation (no LLM — checks if the chat_scan hit survived dedup)
# ---------------------------------------------------------------------------

def _word_overlap(a: str, b: str) -> float:
    """Fraction of words in the shorter string that appear in the longer."""
    wa, wb = set(a.lower().split()), set(b.lower().split())
    if not wa or not wb:
        return 0.0
    return len(wa & wb) / min(len(wa), len(wb))


def _hypothesis_survived(matched_hypothesis: str, dedup_data: dict) -> bool:
    """Return True if the matched_hypothesis text is present in deduped_hypotheses."""
    for entry in dedup_data.get("deduped_hypotheses", []):
        h = entry.get("hypothesis", entry)
        summary = h.get("summary", "")
        if _word_overlap(matched_hypothesis, summary) >= 0.5:
            return True
    return False


def main():
    parser = argparse.ArgumentParser(description="Evaluate vulnerability localization via GPT-4o")
    parser.add_argument("--output-dir", default="output")
    parser.add_argument("--dataset", default="scripts/cve_dataset.jsonl")
    parser.add_argument("--patches-dir", default="scripts/patches")
    parser.add_argument("--agent", choices=[*ALL_AGENTS, "all"], default="all")
    parser.add_argument("--chat-scan-dirs", nargs="*", default=["output/chat_scan"],
                        help="Extra directories of free-form chat_scan runs (CVE ID read from result.json)")
    parser.add_argument("--workers", type=int, default=32, help="Concurrent LLM calls (default: 32)")
    parser.add_argument("--force", action="store_true", help="Re-evaluate even if score.json already exists")
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

    agents_to_eval = ALL_AGENTS if args.agent == "all" else [args.agent]
    all_results = {}

    def _eval_one(agent_key, cve_dir, result_file, extract_fn, cve_id=None):
        """Evaluate a single run dir; returns (agent_key, result_dict) or None to skip."""
        if cve_id is None:
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

        score_path = cve_dir / "score.json"
        if score_path.exists() and not args.force:
            print(f"  SKIP {cve_id} [{agent_key}]: already scored")
            return None

        entry = dataset[cve_id]
        patch_text = patch_path.read_text(errors="replace")
        hypotheses = extract_fn(result_path)
        source_lines = _load_source_lines(result_path)

        verdict = evaluate_with_llm(
            cve_id, hypotheses, source_lines, patch_text,
            entry.get("description", ""), client, model=args.model,
        )

        result = {
            "cve_id": cve_id,
            "hit": verdict["hit"],
            "reasoning": verdict["reasoning"],
            "matched_hypothesis": verdict["matched_hypothesis"],
            "conversation": verdict.get("conversation", []),
        }

        tag = "HIT " if verdict["hit"] else "MISS"
        print(f"  [{tag}] {cve_id} [{agent_key}]: {verdict['reasoning'][:80]}")

        try:
            with open(score_path, "w") as sf:
                json.dump(result, sf, indent=2)
        except Exception as e:
            print(f"  WARNING: failed to write {score_path}: {e}")

        return agent_key, result

    def _find_free_chat_scan_tasks(scan_dir: Path) -> list:
        """Scan a directory of chat_scan run dirs where CVE ID is inside result.json."""
        if not scan_dir.exists():
            return []
        tasks = []
        for run_dir in sorted(scan_dir.iterdir()):
            if not run_dir.is_dir():
                continue
            result_path = run_dir / "result.json"
            if not result_path.exists():
                continue
            try:
                with open(result_path) as f:
                    info = json.load(f).get("info", {})
                file_path = info.get("file_path", "")
                m = re.search(r"(CVE-\d{4}-\d+)", file_path)
                if not m:
                    continue
                cve_id = m.group(1)
            except Exception:
                continue
            tasks.append(("chat_scan", run_dir, "result.json", extract_chat_scan_hypotheses, cve_id))
        return tasks

    def _eval_dedup_one(cve_dir: Path) -> tuple | None:
        """Evaluate batch_dedup without LLM: check if the chat_scan hit survived."""
        cve_id = cve_dir.name
        dedup_result_path = cve_dir / "result.json"
        chat_scan_score_path = base / "batch_chat_scan" / cve_id / "score.json"
        score_path = cve_dir / "score.json"

        if not dedup_result_path.exists():
            print(f"  SKIP {cve_id} [batch_dedup]: no result.json")
            return None
        if not chat_scan_score_path.exists():
            print(f"  SKIP {cve_id} [batch_dedup]: no batch_chat_scan score.json")
            return None
        if score_path.exists() and not args.force:
            print(f"  SKIP {cve_id} [batch_dedup]: already scored")
            return None

        chat_score = json.loads(chat_scan_score_path.read_text())
        dedup_data = json.loads(dedup_result_path.read_text())

        if not chat_score.get("hit"):
            result = {
                "cve_id": cve_id,
                "hit": False,
                "reasoning": "chat_scan did not find a hit; dedup cannot improve on that.",
                "matched_hypothesis": None,
                "conversation": [],
            }
        else:
            matched = chat_score.get("matched_hypothesis") or ""
            survived = _hypothesis_survived(matched, dedup_data)
            result = {
                "cve_id": cve_id,
                "hit": survived,
                "reasoning": (
                    "Matched hypothesis survived dedup." if survived
                    else "Matched hypothesis was removed during dedup."
                ),
                "matched_hypothesis": matched if survived else None,
                "conversation": [],
            }

        tag = "HIT " if result["hit"] else "MISS"
        print(f"  [{tag}] {cve_id} [batch_dedup]: {result['reasoning']}")

        try:
            score_path.write_text(json.dumps(result, indent=2))
        except Exception as e:
            print(f"  WARNING: failed to write {score_path}: {e}")

        return "batch_dedup", result

    # Build all tasks across all agents
    tasks = []
    for agent_key in agents_to_eval:
        if agent_key == "batch_dedup":
            continue  # handled separately below
        dir_name, result_file, extract_fn = AGENT_CONFIGS[agent_key]
        agent_dir = base / dir_name
        if not agent_dir.exists():
            print(f"WARNING: {agent_dir} does not exist, skipping.")
            continue
        for cve_dir in sorted(d for d in agent_dir.iterdir() if d.is_dir() and re.match(r"CVE-", d.name)):
            tasks.append((agent_key, cve_dir, result_file, extract_fn))

    # batch_dedup tasks (no LLM, submitted alongside regular tasks)
    if "batch_dedup" in agents_to_eval:
        dedup_dir = base / "batch_dedup"
        if dedup_dir.exists():
            for cve_dir in sorted(d for d in dedup_dir.iterdir() if d.is_dir() and re.match(r"CVE-", d.name)):
                tasks.append(("batch_dedup", cve_dir))
        else:
            print(f"WARNING: {dedup_dir} does not exist, skipping batch_dedup.")

    # Free-form chat_scan dirs (output/chat_scan/chat-scan_XXXX/)
    if args.agent in ("chat_scan", "all"):
        for free_dir in args.chat_scan_dirs:
            free_tasks = _find_free_chat_scan_tasks(Path(free_dir))
            if free_tasks:
                print(f"Found {len(free_tasks)} free-form chat_scan runs in {free_dir}")
            tasks.extend(free_tasks)

    print(f"Evaluating {len(tasks)} runs with {args.workers} workers...")

    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = {}
        for t in tasks:
            if t[0] == "batch_dedup":
                futures[pool.submit(_eval_dedup_one, t[1])] = t
            else:
                futures[pool.submit(_eval_one, *t)] = t
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



if __name__ == "__main__":
    main()
