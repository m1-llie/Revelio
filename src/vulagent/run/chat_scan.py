#!/usr/bin/env python3
"""Chat-based vulnerability scanner.

Reads a local source file and conducts multi-turn conversations with the model:
1. Summarize the file in two rounds
2. Parse all functions
3. Ask the model about each function individually for vulnerabilities
4. Ask the model to generate a structured JSON report

Examples:
    python -m vulagent.run.chat_scan -f src/parser.c -m claude-haiku-4-5-20251001
    vul-agent-chat-scan --file src/decompressors.rs --model claude-opus-4-6
"""

from __future__ import annotations

import argparse
import ast
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

import litellm

litellm.disable_cache()

#SYSTEM_PROMPT = (
#    "You are an expert software security engineer specializing in vulnerability discovery. "
#    "You analyze source code carefully for security issues including memory safety bugs, "
#    "injection flaws, logic errors, integer overflows, and other vulnerability classes."
#)


# ---------------------------------------------------------------------------
# LiteLLM chat helper
# ---------------------------------------------------------------------------


def chat(messages: list[dict], model: str, **kwargs) -> str:
    """Send messages and return the assistant reply text."""
    response = litellm.completion(model=model, messages=messages, **kwargs)
    return response.choices[0].message.content or ""


def new_session() -> list[dict]:
    return []#[{"role": "system", "content": SYSTEM_PROMPT}]


def send(messages: list[dict], model: str, user_text: str, **kwargs) -> str:
    messages.append({"role": "user", "content": user_text})
    reply = chat(messages, model, **kwargs)
    messages.append({"role": "assistant", "content": reply})
    return reply


# ---------------------------------------------------------------------------
# Function parsing
# ---------------------------------------------------------------------------


class FunctionInfo:
    def __init__(self, name: str, source: str, start_line: int, end_line: int):
        self.name = name
        self.source = source
        self.start_line = start_line
        self.end_line = end_line


def _parse_python(source: str) -> list[FunctionInfo]:
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return []
    lines = source.splitlines()
    results = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            start, end = node.lineno, node.end_lineno or node.lineno
            results.append(FunctionInfo(
                name=node.name,
                source="\n".join(lines[start - 1 : end]),
                start_line=start,
                end_line=end,
            ))
    return results


def _parse_brace_language(source: str, pattern: re.Pattern) -> list[FunctionInfo]:
    results = []
    for m in pattern.finditer(source):
        name = m.group("name")
        brace_pos = source.find("{", m.end() - 1)
        if brace_pos == -1:
            continue
        depth, i = 0, brace_pos
        while i < len(source):
            if source[i] == "{":
                depth += 1
            elif source[i] == "}":
                depth -= 1
                if depth == 0:
                    results.append(FunctionInfo(
                        name=name,
                        source=source[m.start() : i + 1],
                        start_line=source[: m.start()].count("\n") + 1,
                        end_line=source[: i + 1].count("\n") + 1,
                    ))
                    break
            i += 1
    return results


_C_RE = re.compile(
    r"^(?:[\w\s\*]+?\s+)?(?P<name>[a-zA-Z_]\w*)\s*\([^;{]*\)\s*(?:const\s*)?(?:noexcept\s*)?\{",
    re.MULTILINE,
)
_RUST_RE = re.compile(
    r"(?:pub(?:\s*\([^)]*\))?\s+)?(?:async\s+)?(?:unsafe\s+)?fn\s+(?P<name>[a-zA-Z_]\w*)[\s\S]*?\{",
    re.MULTILINE,
)
_GO_RE = re.compile(
    r"^func\s+(?:\([^)]*\)\s*)?(?P<name>[a-zA-Z_]\w*)\s*\([^)]*\)[^{]*\{",
    re.MULTILINE,
)


def parse_functions(file_path: Path, source: str) -> list[FunctionInfo]:
    ext = file_path.suffix.lower()
    if ext == ".py":
        return _parse_python(source)
    if ext in {".c", ".cpp", ".cc", ".cxx", ".h", ".hpp"}:
        return _parse_brace_language(source, _C_RE)
    if ext == ".rs":
        return _parse_brace_language(source, _RUST_RE)
    if ext == ".go":
        return _parse_brace_language(source, _GO_RE)
    funcs = _parse_python(source)
    return funcs if funcs else _parse_brace_language(source, _C_RE)


# ---------------------------------------------------------------------------
# Phases
# ---------------------------------------------------------------------------


HYPOTHESIS_SCHEMA = json.dumps([
    {
        "hypothesis": {
            "summary": "Brief description of the vulnerability",
            "files_reviewed": ["file_path"],
            "harness_entry": "entry function or null",
            "call_chains": ["A -> B -> C"],
            "hotspots": [
                {
                    "file_path": "file.py",
                    "line_start": 42,
                    "line_end": 55,
                    "function": "func_name",
                    "context": "Description of the issue at this location",
                }
            ],
            "warnings": ["Risk or impact description"],
        }
    }
], indent=2)


def _ask_for_json(msgs: list[dict], model: str, kwargs: dict) -> tuple[str, list]:
    """Continue a conversation asking the model to emit hypotheses as JSON.

    Returns (raw_reply, parsed_list). parsed_list is [] on parse failure.
    """
    reply = send(
        msgs, model,
        "Based on your analysis above, please output a JSON list of hypotheses "
        "following this exact schema (output ONLY valid JSON, no prose before or after):\n\n"
        f"```json\n{HYPOTHESIS_SCHEMA}\n```\n\n"
        "One object per distinct vulnerability hypothesis. "
        "Return an empty list [] if no vulnerabilities were found.",
        **kwargs,
    )
    m = re.search(r"```(?:json)?\s*(\[[\s\S]*?\])\s*```", reply)
    raw = m.group(1) if m else reply[reply.find("[") : reply.rfind("]") + 1]
    try:
        return reply, json.loads(raw)
    except json.JSONDecodeError:
        return reply, []


def _truncate(text: str, max_chars: int = 12_000) -> str:
    if len(text) <= max_chars:
        return text
    half = max_chars // 2
    return text[:half] + f"\n\n... [{len(text) - max_chars} chars elided] ...\n\n" + text[-half:]


def phase_summarize(model: str, file_path: Path, source: str, kwargs: dict) -> tuple[str, str, list[dict]]:
    msgs = new_session()
    round1 = send(
        msgs, model,
        f"Here is the file `{file_path.name}`:\n\n```\n{_truncate(source)}\n```\n\n"
        "Please produce a summary of this file. Note that your summary should explain "
        "**all** of the features and functionalities. Do this by checking whether you "
        "can address every line of the file to one of the features/functionalities.",
        **kwargs,
    )
    round2 = send(msgs, model, "good. now please summarize into more high-level features.", **kwargs)
    return round1, round2, msgs


def _func_lines(func: FunctionInfo) -> int:
    return func.end_line - func.start_line + 1


def _make_batches(
    funcs: list[FunctionInfo], short_threshold: int = 100, batch_line_limit: int = 100
) -> list[list[FunctionInfo]]:
    """Group short functions into batches; long functions get their own batch of one."""
    batches: list[list[FunctionInfo]] = []
    current_batch: list[FunctionInfo] = []
    current_lines = 0
    for func in funcs:
        if _func_lines(func) >= short_threshold:
            # flush pending short batch first, then add long func alone
            if current_batch:
                batches.append(current_batch)
                current_batch, current_lines = [], 0
            batches.append([func])
        else:
            if current_lines + _func_lines(func) > batch_line_limit and current_batch:
                batches.append(current_batch)
                current_batch, current_lines = [], 0
            current_batch.append(func)
            current_lines += _func_lines(func)
    if current_batch:
        batches.append(current_batch)
    return batches

def phase_analyze_wholefile(model: str, file_path: Path, summary_msgs: list[dict], kwargs: dict):
    msgs = list(summary_msgs)
    analysis = send(
        msgs, model,
        "Good. now please refer to your own summarization and form some hypothesis about feature-related vulnerabilities. Note that you don't have to cover all the vulnerabilities, just cover **all** of the feature-related ones.\n\nPlease review each feature to form hypothesis. Please think very carefully about the features. Especially do not miss the vulnerabilities related to uncontrolled resource consumption.",
        **kwargs
    )
    _, hypotheses = _ask_for_json(msgs, model, kwargs)
    return {"analysis": analysis, "hypotheses": hypotheses, "messages": msgs}

def phase_analyze_functions(
    model: str, file_path: Path, funcs: list[FunctionInfo], summary_msgs: list[dict], kwargs: dict
) -> dict:
    """Analyze one or more functions in a single conversation pair (two parallel branches)."""
    combined_snippet = "\n\n".join(
        f"Function `{f.name}` (lines {f.start_line}–{f.end_line}):\n"
        f"```\n{_truncate(f.source, 6_000)}\n```"
        for f in funcs
    )
    label = ", ".join(f.name for f in funcs)

    
    # Branch 2: function-specific formulation
    msgs_formulation = list(summary_msgs)
    formulation = send(
        msgs_formulation, model,
        f"Good. Now please examine the following function(s):\n\n{combined_snippet}\n\n"
        "Please refer to your own summarization and form some hypothesis about potential vulnerabilities. "
        "You should try to cover all the vulnerabilities, both feature-related and feature-unrelated.\n\n"
        "Please try to find all the vulnerabilities. Especially do not miss the vulnerabilities related to "
        "uncontrolled resource consumption, and easier vulnerabilities like wrong branch conditions, "
        "missed NULL check, and uninitialized variables.",
        **kwargs
    )
    _, hypotheses = _ask_for_json(msgs_formulation, model, kwargs)

    return {
        "function": label,
        "functions": [{"name": f.name, "start_line": f.start_line, "end_line": f.end_line} for f in funcs],
        "start_line": min(f.start_line for f in funcs),
        "end_line": max(f.end_line for f in funcs),
        "formulation": formulation,
        "hypotheses": hypotheses,
        "messages_formulation": msgs_formulation,
    }


def phase_generate_report(
    model: str, file_path: Path, summary: str, deep_summary: str,
    wholefile_result: dict, function_analyses: list[dict], kwargs: dict,
) -> dict:
    # Collect all per-session hypothesis lists
    all_hypotheses = list(wholefile_result.get("hypotheses", []))
    for fa in function_analyses:
        all_hypotheses.extend(fa.get("hypotheses", []))

    all_hyp_json = json.dumps(all_hypotheses, indent=2)

    msgs = new_session()
    reply = send(
        msgs, model,
        f"The following hypotheses were independently generated across multiple analysis "
        f"sessions of `{file_path.name}`:\n\n"
        f"```json\n{_truncate(all_hyp_json, 12_000)}\n```\n\n"
        f"**File summary:**\n{deep_summary}\n\n"
        "Please deduplicate, merge overlapping entries, and produce a single aggregated "
        "JSON list using the same schema (output ONLY valid JSON, no prose):\n\n"
        f"```json\n{HYPOTHESIS_SCHEMA}\n```\n\n"
        "Preserve all distinct vulnerabilities. Assign a unique `summary` to each. "
        "Return an empty list [] if there are no genuine vulnerabilities.",
        **kwargs,
    )

    m = re.search(r"```(?:json)?\s*(\[[\s\S]*?\])\s*```", reply)
    raw = m.group(1) if m else reply[reply.find("[") : reply.rfind("]") + 1]
    try:
        aggregated = json.loads(raw)
    except json.JSONDecodeError:
        aggregated = all_hypotheses  # fall back to raw collected list

    return {
        "hypotheses": aggregated,
        "per_session_hypotheses": all_hypotheses,
        "generation_notes": reply,
    }


# ---------------------------------------------------------------------------
# Deduplication
# ---------------------------------------------------------------------------


def _hotspots(hyp: dict) -> list[dict]:
    """Extract hotspot list regardless of whether hypothesis is wrapped or flat."""
    return hyp.get("hypothesis", hyp).get("hotspots", [])


def _line_groups(hypotheses: list[dict]) -> list[list[int]]:
    """Union-find grouping of hypotheses that share overlapping hotspot line ranges."""
    n = len(hypotheses)
    parent = list(range(n))

    def find(x: int) -> int:
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(x: int, y: int) -> None:
        parent[find(x)] = find(y)

    for i in range(n):
        for j in range(i + 1, n):
            for hi in _hotspots(hypotheses[i]):
                for hj in _hotspots(hypotheses[j]):
                    if hi.get("file_path") != hj.get("file_path"):
                        continue
                    s1, e1 = hi.get("line_start", 0), hi.get("line_end", 0)
                    s2, e2 = hj.get("line_start", 0), hj.get("line_end", 0)
                    if s1 <= e2 and s2 <= e1:  # ranges overlap
                        union(i, j)

    from collections import defaultdict
    buckets: dict[int, list[int]] = defaultdict(list)
    for i in range(n):
        buckets[find(i)].append(i)
    return list(buckets.values())


def phase_deduplicate(model: str, hypotheses: list[dict], kwargs: dict) -> list[dict]:
    """Deduplicate hypotheses: group by overlapping line ranges, then LLM-merge each group."""
    if len(hypotheses) <= 1:
        return hypotheses

    groups = _line_groups(hypotheses)
    result: list[dict] = []

    for group in groups:
        if len(group) == 1:
            result.append(hypotheses[group[0]])
            continue

        group_hyps = [hypotheses[i] for i in group]
        msgs = new_session()
        reply = send(
            msgs, model,
            "The following vulnerability hypotheses share overlapping code locations "
            "and may describe the same issue:\n\n"
            f"```json\n{_truncate(json.dumps(group_hyps, indent=2), 8_000)}\n```\n\n"
            "Merge into one hypothesis if they describe the same vulnerability; "
            "keep separate if they are genuinely distinct. "
            "Output ONLY a valid JSON list, no prose:\n\n"
            f"```json\n{HYPOTHESIS_SCHEMA}\n```",
            **kwargs,
        )
        m = re.search(r"```(?:json)?\s*(\[[\s\S]*?\])\s*```", reply)
        raw = m.group(1) if m else reply[reply.find("[") : reply.rfind("]") + 1]
        try:
            result.extend(json.loads(raw))
        except json.JSONDecodeError:
            result.extend(group_hyps)  # keep originals on parse failure

    return result


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def main():
    parser = argparse.ArgumentParser(description="Chat-based vulnerability scanner")
    parser.add_argument("-f", "--file", required=True, help="Source file to analyze")
    parser.add_argument("-m", "--model", default=os.getenv("MSWEA_MODEL_NAME"), help="Model name")
    parser.add_argument("-b", "--base-url", default=None, help="LiteLLM proxy base URL")
    parser.add_argument("-k", "--api-key", default=os.getenv("MSWEA_MODEL_API_KEY"), help="API key")
    parser.add_argument("-o", "--output", default=None, help="Output JSON path")
    parser.add_argument("--max-functions", type=int, default=50, help="Max functions to analyze")
    args = parser.parse_args()

    file_path = Path(args.file).resolve()
    if not file_path.is_file():
        print(f"Error: file not found: {file_path}", file=sys.stderr)
        sys.exit(1)

    model_name = args.model
    if not model_name:
        print("Error: no model specified. Use --model or set MSWEA_MODEL_NAME.", file=sys.stderr)
        sys.exit(1)

    if args.output:
        output_path = Path(args.output)
    else:
        ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
        output_path = Path("output/chat_scan") / f"chat-scan_{file_path.stem}_{ts}" / "result.json"
    output_path.parent.mkdir(parents=True, exist_ok=True)

    model_kwargs: dict = {"temperature": 1.0, "drop_params": True}
    if args.base_url:
        model_kwargs["base_url"] = args.base_url
    if args.api_key:
        model_kwargs["api_key"] = args.api_key

    print(f"File:   {file_path}")
    print(f"Model:  {model_name}")
    print(f"Output: {output_path}")

    source = file_path.read_text(errors="replace")
    started_at = datetime.now(timezone.utc)

    # Phase 1: summarize
    print("\nPhase 1: Summarizing file (2 rounds)...")
    summary, deep_summary, summary_msgs = phase_summarize(model_name, file_path, source, model_kwargs)
    print(f"  Round 1: {len(summary)} chars  |  Round 2: {len(deep_summary)} chars")

    # Phase 2: parse functions
    print("\nPhase 2: Parsing functions...")
    functions = parse_functions(file_path, source)
    total_found = len(functions)
    if total_found > args.max_functions:
        print(f"  Found {total_found}, limiting to {args.max_functions}")
        functions = functions[: args.max_functions]
    else:
        print(f"  Found {total_found} functions")

    # Phase 3a: whole-file feature-level analysis
    print("\nPhase 3a: Whole-file feature-level analysis...")
    wholefile_result = phase_analyze_wholefile(model_name, file_path, summary_msgs, model_kwargs)
    print(f"  Done ({len(wholefile_result['analysis'])} chars)")

    # Phase 3b: analyze functions, batching short ones together
    batches = _make_batches(functions)
    print(f"\nPhase 3b: Analyzing {len(functions)} functions in {len(batches)} conversation(s)...")
    function_analyses: list[dict] = []
    for i, batch in enumerate(batches, 1):
        label = ", ".join(f.name for f in batch)
        print(f"  [{i}/{len(batches)}] {label}... ", end="", flush=True)
        result = phase_analyze_functions(model_name, file_path, batch, summary_msgs, model_kwargs)
        print("VULNERABLE" if result.get("has_vulnerability") else "OK")
        function_analyses.append(result)

    # Phase 4: aggregate per-session hypotheses
    print("\nPhase 4: Aggregating hypotheses...")
    report = phase_generate_report(
        model_name, file_path, summary, deep_summary, wholefile_result, function_analyses, model_kwargs
    )
    aggregated = report.get("hypotheses", [])
    print(f"  {len(report.get('per_session_hypotheses', []))} raw → {len(aggregated)} after aggregation")

    # Phase 5: deduplicate
    print("\nPhase 5: Deduplicating hypotheses...")
    groups = _line_groups(aggregated)
    n_groups = sum(1 for g in groups if len(g) > 1)
    print(f"  {len(aggregated)} hypotheses, {n_groups} overlap group(s) to merge")
    deduplicated = phase_deduplicate(model_name, aggregated, model_kwargs)
    print(f"  {len(deduplicated)} hypotheses after deduplication")

    finished_at = datetime.now(timezone.utc)
    vulnerable_count = sum(1 for fa in function_analyses if fa.get("has_vulnerability"))
    print(f"\nDone: {len(deduplicated)} final hypotheses")

    output_data = {
        "info": {
            "file_path": str(file_path),
            "model": model_name,
            "started_at_utc": started_at.isoformat(),
            "finished_at_utc": finished_at.isoformat(),
            "duration_seconds": (finished_at - started_at).total_seconds(),
            "functions_found": total_found,
            "functions_analyzed": len(function_analyses),
            "vulnerable_count": vulnerable_count,
        },
        "summary": summary,
        "deep_summary": deep_summary,
        "wholefile_analysis": wholefile_result["analysis"],
        "function_analyses": [{k: v for k, v in fa.items() if not k.startswith("messages_")} for fa in function_analyses],
        "hypotheses": deduplicated,
        "hypotheses_pre_dedup": aggregated,
        "conversation_log": {
            "summary_phase": summary_msgs,
            "wholefile_analysis": wholefile_result.get("messages", []),
            "function_analyses": [
                {
                    "function": fa["function"],
                    "messages_formulation": fa["messages_formulation"],
                }
                for fa in function_analyses
            ],
        },
    }

    output_path.write_text(json.dumps(output_data, indent=2))
    print(f"Saved to: {output_path}")


if __name__ == "__main__":
    main()
