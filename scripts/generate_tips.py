#!/usr/bin/env python3
"""Generate vulnerability-finding tips for single-file CVEs.

For each single-file CVE in cve_dataset.jsonl that has a patch, asks an LLM
to produce a concise, general tip that helps a security analyst find this
class of vulnerability when reviewing a function.

Output: a JSONL file where each line is:
  {"cve_id": ..., "description": ..., "tip": ..., "cwe_ids": [...]}

Examples:
    python scripts/generate_tips.py --model claude-haiku-4-5-20251001
    python scripts/generate_tips.py \\
        --model litellm_proxy/vertex_ai/claude-haiku-4-5@20251001 \\
        --base-url https://litellm-991596698159.us-west1.run.app \\
        --api-key sk-... --workers 16 --output tips.jsonl
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

import litellm

DATASET_PATH = Path("/srv/share/vulagent/cve_dataset.jsonl")
PATCHES_DIR = Path("/srv/home/tony/vul-agent/scripts/patches")

PROMPT_TEMPLATE = """\
You are a security expert. Below is a CVE description and the ground-truth patch that fixed it.

CVE ID: {cve_id}
Description: {description}

Patch:
```diff
{patch}
```

Based on the description and patch, produce a SHORT, GENERAL tip (1-2 sentences) that would help a \
security analyst find this class of vulnerability when reviewing source code — specifically when \
they are given a single function to inspect.

The tip should:
- Be actionable and concrete (e.g. "check whether X is validated before Y")
- Be general enough to apply to similar vulnerabilities, not just this exact CVE
- NOT mention the CVE ID, specific file names, or specific line numbers
- Focus on what pattern or assumption to look for in the code

First, briefly reason about what the root cause is and what a reviewer should watch for.
Then output your final tip inside <tip>...</tip> tags."""


def load_candidates(dataset_path: Path, patches_dir: Path) -> list[dict]:
    candidates = []
    with open(dataset_path) as f:
        for line in f:
            entry = json.loads(line)
            if not entry.get("is_single_file"):
                continue
            if not entry.get("validation_valid"):
                continue
            patch_path = patches_dir / f"{entry['cve_id']}.patch"
            if not patch_path.exists():
                continue
            entry["_patch_path"] = patch_path
            candidates.append(entry)
    return candidates


def generate_tip(entry: dict, model: str, kwargs: dict) -> dict:
    patch_text = Path(entry["_patch_path"]).read_text(errors="replace")
    prompt = PROMPT_TEMPLATE.format(
        cve_id=entry["cve_id"],
        description=entry.get("description", ""),
        patch=patch_text[:6000],
    )

    max_retries, base_delay = 8, 4.0
    for attempt in range(max_retries):
        try:
            resp = litellm.completion(
                model=model,
                messages=[{"role": "user", "content": prompt}],
                **kwargs,
            )
            full_response = (resp.choices[0].message.content or "").strip()
            import re
            m = re.search(r"<tip>([\s\S]*?)</tip>", full_response)
            tip = m.group(1).strip() if m else full_response
            return {
                "cve_id": entry["cve_id"],
                "description": entry.get("description", ""),
                "cwe_ids": entry.get("cwe_ids", []),
                "files": entry.get("files", []),
                "tip": tip,
                "reasoning": full_response if m else "",
            }
        except litellm.RateLimitError:
            if attempt == max_retries - 1:
                raise
            time.sleep(base_delay * (2 ** attempt))

    raise RuntimeError("Max retries exceeded")


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate vulnerability-finding tips for single-file CVEs")
    parser.add_argument("-m", "--model", default=os.getenv("MSWEA_MODEL_NAME"), help="Model name")
    parser.add_argument("-b", "--base-url", default=None, help="LiteLLM proxy base URL")
    parser.add_argument("-k", "--api-key", default=os.getenv("MSWEA_MODEL_API_KEY"), help="API key")
    parser.add_argument("-o", "--output", default="scripts/tips.jsonl", help="Output JSONL path")
    parser.add_argument("--dataset", default=str(DATASET_PATH), help="Path to cve_dataset.jsonl")
    parser.add_argument("--patches-dir", default=str(PATCHES_DIR), help="Directory containing patches")
    parser.add_argument("--workers", type=int, default=16, help="Parallel workers")
    parser.add_argument("--limit", type=int, default=None, help="Process only N CVEs")
    parser.add_argument("--cve", default=None, help="Generate tip for a single CVE ID only")
    args = parser.parse_args()

    model = args.model
    if not model:
        print("Error: no model specified. Use --model or set MSWEA_MODEL_NAME.", file=sys.stderr)
        sys.exit(1)

    model_kwargs: dict = {"temperature": 0.7, "drop_params": True, "max_tokens": 2048}
    if args.base_url:
        model_kwargs["base_url"] = args.base_url
    if args.api_key:
        model_kwargs["api_key"] = args.api_key

    candidates = load_candidates(Path(args.dataset), Path(args.patches_dir))
    candidates.sort(key=lambda c: c["cve_id"], reverse=True)
    print(f"Found {len(candidates)} single-file CVEs with patches")

    if args.cve:
        match = [c for c in candidates if c["cve_id"] == args.cve]
        if not match:
            print(f"Error: {args.cve} not found in dataset or has no patch.", file=sys.stderr)
            sys.exit(1)
        result = generate_tip(match[0], model, model_kwargs)
        print(f"\n{result['cve_id']}")
        if result.get("reasoning"):
            print(f"Reasoning:\n{result['reasoning']}\n")
        print(f"Tip:\n{result['tip']}")
        return

    # Skip already-processed CVEs
    output_path = Path(args.output)
    done: set[str] = set()
    if output_path.exists():
        with open(output_path) as f:
            for line in f:
                try:
                    done.add(json.loads(line)["cve_id"])
                except Exception:
                    pass
        print(f"Skipping {len(done)} already processed")

    remaining = [c for c in candidates if c["cve_id"] not in done]
    if args.limit:
        remaining = remaining[: args.limit]

    print(f"Processing {len(remaining)} CVEs with {args.workers} workers...")
    print(f"Output: {output_path}\n")

    output_path.parent.mkdir(parents=True, exist_ok=True)
    completed = failed = 0

    with open(output_path, "a") as out_f:
        with ThreadPoolExecutor(max_workers=args.workers) as pool:
            futures = {pool.submit(generate_tip, entry, model, model_kwargs): entry for entry in remaining}
            total = len(futures)
            for future in as_completed(futures):
                entry = futures[future]
                completed += 1
                try:
                    result = future.result()
                    out_f.write(json.dumps(result) + "\n")
                    out_f.flush()
                    print(f"  [{completed}/{total}] {result['cve_id']}: {result['tip'][:80]}...")
                except Exception as e:
                    failed += 1
                    print(f"  [{completed}/{total}] ERROR {entry['cve_id']}: {e}", file=sys.stderr)

    print(f"\nDone. Successful: {completed - failed}  Failed: {failed}")
    print(f"Output: {output_path}")


if __name__ == "__main__":
    main()
