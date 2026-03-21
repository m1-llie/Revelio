#!/usr/bin/env python3
"""Sequentially process tips.jsonl to:

1. RAG check: ask the LLM whether the tip is retrievable via RAG — i.e., general
   enough to surface similar vulnerabilities in other functions.

2. Prompt evolution: iteratively refine a growing general vulnerability-finding
   prompt by incorporating each CVE's pattern.

State is saved after every CVE so the script is safely resumable.

Output files:
  scripts/rag_checks.jsonl   — per-CVE RAG evaluation results
  scripts/general_prompt.md  — the evolving general prompt (updated in-place)

Examples:
    python scripts/build_general_prompt.py --model claude-haiku-4-5-20251001
    python scripts/build_general_prompt.py \\
        --model litellm_proxy/vertex_ai/claude-haiku-4-5@20251001 \\
        --base-url https://litellm-991596698159.us-west1.run.app \\
        --api-key sk-... --limit 50
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path

import litellm

TIPS_PATH = Path("scripts/tips.jsonl")
RAG_CHECKS_PATH = Path("scripts/rag_checks.jsonl")
GENERAL_PROMPT_PATH = Path("scripts/general_prompt.md")

INITIAL_PROMPT = """\
# General Vulnerability-Finding Tips

When reviewing a function for security vulnerabilities, consider the following patterns:

(No patterns yet — will be built iteratively.)
"""

RAG_CHECK_PROMPT = """\
You are evaluating the property of a vulnerability.

CVE ID: {cve_id}
Description: {description}

Patch:
```diff
{patch}
```

Tip: {tip}

Answer the following two questions:

1. **Specific enough**: Is this CVE feature-specific? A guideline:
    - First ask: how hard it is to understand the patch given the description? Do I need to understand more about the repository?
    - Next ask: Is it possible to have the same vulnerability somewhere else? Is it possible that this type of vulnerability happens in completely irrelevant scenarios?
    If the understanding of the vulnerability is easy and it is possible for the vulnerability to take place in other scenarios, then this CVE is not specific enough.

2. **General enough**: Is this tip general enough to apply across different codebases and functions — not just to this exact CVE? A criteria is that the tip should not mention any names specific to the repository.

First, briefly reason about each question. Then output your final answer inside <json>...</json> tags:
<json>
{{"specific_enough": true|false, "general_enough": true|false, \
"reasoning": "one sentence"}}
</json>"""

UPDATE_PROMPT = """\
You are building a general security vulnerability-finding prompt for use by a security analyst \
reviewing source code functions.

Here is the current general prompt:
<current_prompt>
{current_prompt}
</current_prompt>

A new vulnerability pattern has been observed (CVE {cve_id}):
- Description: {description}
- Tip: {tip}

Update the general prompt to incorporate this new pattern if it adds something new or refines \
an existing point. The updated prompt must:
- List concrete, actionable patterns a security analyst should check when reviewing a function
- Be ordered roughly by generality/importance (most general first)
- Never mention specific CVE IDs, file names, or line numbers
- Use concise bullet points (one per distinct pattern)
- Merge overlapping patterns rather than duplicating them

If there is one or more existing bullet points that highly overlaps with this CVE, please DO NOT CREATE A NEW POINT. Simple refine the existing bullet points.
Please keep each bullet point short. At most 4 sentences.

Output ONLY the updated general prompt in Markdown, starting with the `# General Vulnerability-Finding Tips` heading. No preamble."""

REFINE_TIP_PROMPT = """\
The following vulnerability tip is too specific to one CVE and would not generalise well \
across different codebases or functions.

Original tip: {tip}

CVE description (for context): {description}

Rewrite the tip so that it:
- Describes the general class of vulnerability, not the specific CVE
- Is applicable across different programming languages and codebases
- Remains actionable (tells the analyst what to look for)
- Is 1-2 sentences

First, reason about how to best generalise the tip. Then output the refined tip inside <tip>...</tip> tags."""


# ---------------------------------------------------------------------------
# LLM helper
# ---------------------------------------------------------------------------


def _call(model: str, prompt: str, kwargs: dict) -> str:
    max_retries, base_delay = 8, 4.0
    for attempt in range(max_retries):
        try:
            resp = litellm.completion(
                model=model,
                messages=[{"role": "user", "content": prompt}],
                **kwargs,
            )
            return (resp.choices[0].message.content or "").strip()
        except litellm.RateLimitError:
            if attempt == max_retries - 1:
                raise
            time.sleep(base_delay * (2 ** attempt))
    raise RuntimeError("Unreachable")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main() -> None:
    parser = argparse.ArgumentParser(description="Build a general vulnerability-finding prompt from tips")
    parser.add_argument("-m", "--model", default=os.getenv("MSWEA_MODEL_NAME"))
    parser.add_argument("-b", "--base-url", default=None)
    parser.add_argument("-k", "--api-key", default=os.getenv("MSWEA_MODEL_API_KEY"))
    parser.add_argument("--tips", default=str(TIPS_PATH), help="Input tips JSONL")
    parser.add_argument("--rag-checks", default=str(RAG_CHECKS_PATH), help="Output RAG checks JSONL")
    parser.add_argument("--general-prompt", default=str(GENERAL_PROMPT_PATH), help="Output general prompt MD")
    parser.add_argument("--patches-dir", default="scripts/patches")
    parser.add_argument("--limit", type=int, default=None, help="Process only N tips")
    args = parser.parse_args()

    model = args.model
    if not model:
        print("Error: no model specified.", file=sys.stderr)
        sys.exit(1)

    rag_kwargs: dict = {"temperature": 0.7, "drop_params": True, "max_tokens": 1024}
    update_kwargs: dict = {"temperature": 0.3, "drop_params": True, "max_tokens": 4096}
    if args.base_url:
        rag_kwargs["base_url"] = args.base_url
        update_kwargs["base_url"] = args.base_url
    if args.api_key:
        rag_kwargs["api_key"] = args.api_key
        update_kwargs["api_key"] = args.api_key

    # Load tips
    tips = [json.loads(l) for l in open(args.tips)]
    print(f"Loaded {len(tips)} tips")

    # Load already-processed CVE IDs
    rag_path = Path(args.rag_checks)
    done: set[str] = set()
    if rag_path.exists():
        with open(rag_path) as f:
            for line in f:
                try:
                    done.add(json.loads(line)["cve_id"])
                except Exception:
                    pass
        print(f"Skipping {len(done)} already processed")

    # Load or init general prompt
    gp_path = Path(args.general_prompt)
    current_prompt = gp_path.read_text() if gp_path.exists() else INITIAL_PROMPT
    patches_dir = Path(args.patches_dir)

    remaining = [t for t in tips if t["cve_id"] not in done]
    if args.limit:
        remaining = remaining[: args.limit]
    print(f"Processing {len(remaining)} tips sequentially...\n")

    with open(rag_path, "a") as rag_f:
        for i, tip_entry in enumerate(remaining, 1):
            cve_id = tip_entry["cve_id"]
            tip = tip_entry.get("tip", "")
            description = tip_entry.get("description", "")
            patch_path = patches_dir / f"{cve_id}.patch"
            patch = patch_path.read_text(errors="replace")[:4000] if patch_path.exists() else ""

            print(f"[{i}/{len(remaining)}] {cve_id}")

            # --- Task 1: RAG check ---
            rag_prompt = RAG_CHECK_PROMPT.format(
                cve_id=cve_id, description=description, patch=patch, tip=tip
            )
            try:
                raw = _call(model, rag_prompt, rag_kwargs)
                import re
                m = re.search(r"<json>([\s\S]*?)</json>", raw)
                json_str = m.group(1).strip() if m else re.search(r"\{[\s\S]*\}", raw).group(0)
                rag_result = json.loads(json_str)
            except Exception as e:
                rag_result = {"error": str(e)}

            specific_enough = rag_result.get("specific_enough", True)
            general_enough = rag_result.get("general_enough", True)
            print(f"  specific_enough: {specific_enough}  general_enough: {general_enough} — {rag_result.get('reasoning', '')[:70]}")

            # --- Refine tip if not general enough ---
            refined_tip = tip
            if not general_enough:
                try:
                    raw_refined = _call(model, REFINE_TIP_PROMPT.format(
                        tip=tip, description=description,
                    ), rag_kwargs)
                    m = re.search(r"<tip>([\s\S]*?)</tip>", raw_refined)
                    refined_tip = m.group(1).strip() if m else raw_refined
                    print(f"  Tip refined: {refined_tip[:80]}...")
                except Exception as e:
                    print(f"  WARNING: tip refinement failed: {e}", file=sys.stderr)

            rag_record = {"cve_id": cve_id, "tip": tip, "refined_tip": refined_tip, **rag_result}
            rag_f.write(json.dumps(rag_record) + "\n")
            rag_f.flush()

            # --- Task 2: Update general prompt only if NOT RAG-retrievable ---
            if not specific_enough:
                update_prompt = UPDATE_PROMPT.format(
                    current_prompt=current_prompt,
                    cve_id=cve_id,
                    description=description,
                    tip=refined_tip,
                )
                try:
                    updated = _call(model, update_prompt, update_kwargs)
                    if updated.startswith("#"):
                        current_prompt = updated
                        print(f"  General prompt updated ({len(current_prompt)} chars)")
                    else:
                        print(f"  WARNING: unexpected prompt output, keeping previous")
                except Exception as e:
                    print(f"  ERROR updating general prompt: {e}", file=sys.stderr)
            else:
                print(f"  Skipping general prompt update (RAG-retrievable)")

            # Always write the current prompt so progress is visible after each CVE
            gp_path.write_text(current_prompt)

    print(f"\nDone.")
    print(f"RAG checks:     {rag_path}")
    print(f"General prompt: {gp_path}")


if __name__ == "__main__":
    main()
