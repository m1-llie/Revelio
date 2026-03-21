#!/usr/bin/env python3
"""Scan-and-filter pipeline: hypothesis generation -> dedup -> Docker sub-agent filtering.

Given a source file in a repository, this script:
1. Generates vulnerability hypotheses via multi-pass LLM analysis
2. Classifies & deduplicates them
3. Launches parallel Docker sub-agents (mini-SWE style) that spin up a
   container with the full repo, inspect the code around each hypothesis,
   and verdict VALID/INVALID

Fully self-contained — does not import from chat_scan or dedup.

Examples:
    python -m vulagent.run.scan_and_filter -f src/parser.c \\
        -m claude-haiku-4-5-20251001 --repo /path/to/repo

    python -m vulagent.run.scan_and_filter \\
        -f src/parser.c --repo /path/to/repo \\
        -m litellm_proxy/vertex_ai/claude-haiku-4-5@20251001 \\
        --base-url https://litellm-proxy --api-key sk-... \\
        --filter-model litellm_proxy/vertex_ai/claude-sonnet-4-6@20250514 \\
        --workers 8
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import re
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import litellm

litellm.disable_cache()

logger = logging.getLogger("scan_and_filter")


# ===========================================================================
# LLM helpers
# ===========================================================================


def _llm_call(model: str, messages: list[dict], kwargs: dict) -> str:
    """Call LLM with retry on rate limits."""
    max_retries, base_delay = 8, 5.0
    for attempt in range(max_retries):
        try:
            resp = litellm.completion(model=model, messages=messages, **kwargs)
            return resp.choices[0].message.content or ""
        except litellm.RateLimitError:
            if attempt == max_retries - 1:
                raise
            time.sleep(base_delay * (2 ** attempt))
    raise RuntimeError("Unreachable")


def _chat_send(messages: list[dict], model: str, user_text: str, kwargs: dict) -> str:
    """Append user message, call LLM, append assistant reply, return reply."""
    messages.append({"role": "user", "content": user_text})
    reply = _llm_call(model, messages, kwargs)
    messages.append({"role": "assistant", "content": reply})
    return reply


def _extract_json_block(text: str, array: bool = True) -> tuple[str, str]:
    """Extract JSON from ```json ... ``` fences or bare text.

    Returns (reasoning_text, json_string).
    """
    opener = r"\[" if array else r"\{"
    closer = r"\]" if array else r"\}"
    pattern = r"```(?:json)?\s*(" + opener + r"[\s\S]*?" + closer + r")\s*```"
    m = re.search(pattern, text)
    if m:
        return text[: m.start()].strip(), m.group(1)
    # Fallback: find the first bare JSON structure
    bare = re.search(opener + r"[\s\S]*" + closer, text)
    if bare:
        return text[: bare.start()].strip(), bare.group(0)
    return text, "[]" if array else "{}"


def _truncate(text: str, max_chars: int = 12_000) -> str:
    if len(text) <= max_chars:
        return text
    half = max_chars // 2
    return text[:half] + f"\n\n... [{len(text) - max_chars} chars elided] ...\n\n" + text[-half:]


# ===========================================================================
# Function parsing (tree-sitter)
# ===========================================================================


@dataclass
class FunctionInfo:
    name: str
    source: str
    start_line: int
    end_line: int


def _ts_parse(source: str, ts_module: Any, func_types: dict[str, str],
              language_fn: str = "language") -> list[FunctionInfo]:
    try:
        from tree_sitter import Language, Parser
    except ImportError:
        return []
    lang = Language(getattr(ts_module, language_fn)())
    parser = Parser(lang)
    tree = parser.parse(source.encode(errors="replace"))
    lines = source.splitlines()
    results: list[FunctionInfo] = []

    def walk(node: Any) -> None:
        name_type = func_types.get(node.type)
        if name_type:
            for child in node.children:
                if child.type == name_type:
                    start = node.start_point[0] + 1
                    end = node.end_point[0] + 1
                    results.append(FunctionInfo(
                        name=child.text.decode(),
                        source="\n".join(lines[start - 1: end]),
                        start_line=start,
                        end_line=end,
                    ))
                    break
        for child in node.children:
            walk(child)
    walk(tree.root_node)
    return results


def _parse_c(source: str) -> list[FunctionInfo]:
    try:
        import tree_sitter_c as tsc
        from tree_sitter import Language, Parser
    except ImportError:
        return []
    lang = Language(tsc.language())
    parser = Parser(lang)
    tree = parser.parse(source.encode(errors="replace"))
    lines = source.splitlines()
    results: list[FunctionInfo] = []

    def get_name(node: Any) -> str | None:
        for child in node.children:
            if child.type == "function_declarator":
                for c in child.children:
                    if c.type == "identifier":
                        return c.text.decode()
            if child.type == "pointer_declarator":
                for c in child.children:
                    if c.type == "function_declarator":
                        for cc in c.children:
                            if cc.type == "identifier":
                                return cc.text.decode()
        return None

    def walk(node: Any) -> None:
        if node.type == "function_definition":
            name = get_name(node)
            if name:
                start = node.start_point[0] + 1
                end = node.end_point[0] + 1
                results.append(FunctionInfo(
                    name=name,
                    source="\n".join(lines[start - 1: end]),
                    start_line=start,
                    end_line=end,
                ))
        for child in node.children:
            walk(child)
    walk(tree.root_node)
    return results


def _remove_overlapping(funcs: list[FunctionInfo]) -> list[FunctionInfo]:
    sorted_funcs = sorted(funcs, key=lambda f: (f.start_line, f.end_line))
    result: list[FunctionInfo] = []
    max_end = -1
    for f in sorted_funcs:
        if f.start_line > max_end:
            result.append(f)
            max_end = f.end_line
    return result


def parse_functions(file_path: Path, source: str) -> list[FunctionInfo]:
    ext = file_path.suffix.lower()
    if ext in {".c", ".cpp", ".cc", ".cxx", ".h", ".hpp"}:
        funcs = _parse_c(source)
    elif ext == ".py":
        try:
            import tree_sitter_python as tspy
        except ImportError:
            return []
        funcs = _ts_parse(source, tspy, {"function_definition": "identifier"})
    elif ext == ".rs":
        try:
            import tree_sitter_rust as tsr
        except ImportError:
            return []
        funcs = _ts_parse(source, tsr, {"function_item": "identifier"})
    elif ext == ".go":
        try:
            import tree_sitter_go as tsg
        except ImportError:
            return []
        funcs = _ts_parse(source, tsg, {
            "function_declaration": "identifier",
            "method_declaration": "field_identifier",
        })
    elif ext in {".ts", ".tsx"}:
        try:
            import tree_sitter_typescript as tst
        except ImportError:
            return []
        funcs = _ts_parse(source, tst, {
            "function_declaration": "identifier",
            "method_definition": "property_identifier",
        }, language_fn="language_typescript")
    elif ext in {".mjs", ".js", ".jsx"}:
        try:
            import tree_sitter_javascript as tsj
        except ImportError:
            return []
        funcs = _ts_parse(source, tsj, {
            "function_declaration": "identifier",
            "method_definition": "property_identifier",
        })
    else:
        return []
    return _remove_overlapping(funcs)


# ===========================================================================
# Stage 1: Hypothesis generation
# ===========================================================================


HYPOTHESIS_SCHEMA = json.dumps([{
    "hypothesis": {
        "summary": "Brief description of the vulnerability",
        "files_reviewed": ["file_path"],
        "harness_entry": "entry function or null",
        "call_chains": ["A -> B -> C"],
        "hotspots": [{
            "file_path": "file.c",
            "line_start": 42,
            "line_end": 55,
            "function": "func_name",
            "context": "Description of the issue at this location",
        }],
        "warnings": ["Risk or impact description"],
    }
}], indent=2)


def _ask_for_json(msgs: list[dict], model: str, kwargs: dict) -> tuple[str, list]:
    """Continue conversation asking for hypotheses as JSON. Returns (raw_reply, parsed_list)."""
    reply = _chat_send(
        msgs, model,
        "Based on your analysis above, please output a JSON list of hypotheses "
        "following this exact schema (output ONLY valid JSON, no prose before or after):\n\n"
        f"```json\n{HYPOTHESIS_SCHEMA}\n```\n\n"
        "One object per distinct vulnerability hypothesis. "
        "Return an empty list [] if no vulnerabilities were found.",
        kwargs,
    )
    _, raw_json = _extract_json_block(reply, array=True)
    try:
        return reply, json.loads(raw_json)
    except json.JSONDecodeError:
        return reply, []


def phase_summarize(model: str, file_path: Path, source: str, kwargs: dict) -> tuple[str, str, list[dict]]:
    msgs: list[dict] = []
    round1 = _chat_send(
        msgs, model,
        f"Here is the file `{file_path.name}`:\n\n```\n{_truncate(source)}\n```\n\n"
        "Please produce a summary of this file. Note that your summary should explain "
        "**all** of the features and functionalities. Do this by checking whether you "
        "can address every line of the file to one of the features/functionalities.",
        kwargs,
    )
    round2 = _chat_send(msgs, model, "good. now please summarize into more high-level features.", kwargs)
    return round1, round2, msgs


def _make_batches(funcs: list[FunctionInfo], short_threshold: int = 100,
                  batch_line_limit: int = 100) -> list[list[FunctionInfo]]:
    batches: list[list[FunctionInfo]] = []
    current_batch: list[FunctionInfo] = []
    current_lines = 0
    for func in funcs:
        n_lines = func.end_line - func.start_line + 1
        if n_lines >= short_threshold:
            if current_batch:
                batches.append(current_batch)
                current_batch, current_lines = [], 0
            batches.append([func])
        else:
            if current_lines + n_lines > batch_line_limit and current_batch:
                batches.append(current_batch)
                current_batch, current_lines = [], 0
            current_batch.append(func)
            current_lines += n_lines
    if current_batch:
        batches.append(current_batch)
    return batches


def phase_analyze_wholefile(model: str, file_path: Path, summary_msgs: list[dict], kwargs: dict) -> dict:
    msgs = list(summary_msgs)
    analysis = _chat_send(
        msgs, model,
        "Good. now please refer to your own summarization and form some hypothesis about "
        "feature-related vulnerabilities. Note that you don't have to cover all the "
        "vulnerabilities, just cover **all** of the feature-related ones.\n\n"
        "Please review each feature to form hypothesis. Please think very carefully about "
        "the features. Especially do not miss the vulnerabilities related to uncontrolled "
        "resource consumption.",
        kwargs,
    )
    _, hypotheses = _ask_for_json(msgs, model, kwargs)
    return {"analysis": analysis, "hypotheses": hypotheses, "messages": msgs}


FOCUSED_PASSES = [
    "Good. Now please re-examine the code under the following assumption: **every pointer can be NULL**. "
    "For each pointer dereference, check whether a NULL value could reach it and what the consequence "
    "would be. Form hypotheses for any potential NULL pointer dereference vulnerabilities you find.",

    "Good. Now please re-examine the code under the following assumption: **every if condition may be "
    "written wrong** — i.e. the branch condition could be written wrong. For each if statement, check "
    "if the branch conditions are written correctly. Form hypotheses for any potential logic errors, "
    "missing checks, or incorrect branch conditions you find.",
]


def phase_analyze_focused(model: str, file_path: Path, summary_msgs: list[dict],
                          focus_prompt: str, kwargs: dict) -> dict:
    msgs = list(summary_msgs)
    analysis = _chat_send(msgs, model, focus_prompt, kwargs)
    _, hypotheses = _ask_for_json(msgs, model, kwargs)
    return {"focus_prompt": focus_prompt, "analysis": analysis, "hypotheses": hypotheses, "messages": msgs}


def phase_analyze_functions(model: str, file_path: Path, funcs: list[FunctionInfo],
                            summary_msgs: list[dict], kwargs: dict) -> dict:
    combined_snippet = "\n\n".join(
        f"Function `{f.name}` (lines {f.start_line}–{f.end_line}):\n"
        f"```\n{_truncate(f.source, 6_000)}\n```"
        for f in funcs
    )
    label = ", ".join(f.name for f in funcs)

    msgs = list(summary_msgs)
    formulation = _chat_send(
        msgs, model,
        f"Good. Now please examine the following function(s):\n\n{combined_snippet}\n\n"
        "Please refer to your own summarization and form some hypothesis about potential "
        "vulnerabilities. You should try to cover all the vulnerabilities, both feature-related "
        "and feature-unrelated.\n\n"
        "Please try to find all the vulnerabilities. Especially do not miss the vulnerabilities "
        "related to uncontrolled resource consumption, and more classic vulnerabilities like "
        "wrong if-clause conditions, missed NULL check, and uninitialized variables.",
        kwargs,
    )
    _, hypotheses = _ask_for_json(msgs, model, kwargs)
    return {
        "function": label,
        "functions": [{"name": f.name, "start_line": f.start_line, "end_line": f.end_line} for f in funcs],
        "start_line": min(f.start_line for f in funcs),
        "end_line": max(f.end_line for f in funcs),
        "formulation": formulation,
        "hypotheses": hypotheses,
        "messages_formulation": msgs,
    }


def aggregate_hypotheses(
    wholefile_result: dict,
    focused_results: list[dict],
    function_analyses: list[dict],
) -> list[dict]:
    all_hyps: list[dict] = list(wholefile_result.get("hypotheses", []))
    for fr in focused_results:
        all_hyps.extend(fr.get("hypotheses", []))
    for fa in function_analyses:
        all_hyps.extend(fa.get("hypotheses", []))
    return all_hyps


# ===========================================================================
# Stage 2: Classification & Dedup
# ===========================================================================


def _format_hypothesis_text(hyp: dict, source_lines: list[str] | None = None) -> str:
    h = hyp.get("hypothesis", hyp)
    parts = []
    if h.get("summary"):
        parts.append(f"Summary: {h['summary']}")
    hotspots = h.get("hotspots", [])
    if hotspots:
        for hs in hotspots:
            loc = f"{hs.get('file_path', '')}:{hs.get('line_start')}-{hs.get('line_end')}"
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


def classify_hypothesis(hyp: dict, model: str, kwargs: dict,
                        source_lines: list[str] | None = None) -> dict:
    """Ask LLM: is this a real vulnerability? Is it ASAN-triggerable? What CWE IDs?"""
    text = _format_hypothesis_text(hyp, source_lines)
    prompt = (
        "You are a security expert. Given the following vulnerability hypothesis, answer:\n\n"
        f"{text}\n\n"
        "Think step by step:\n"
        "1. What does the code do? What is the hypothesis claiming?\n"
        "2. Is this a genuine security vulnerability, or is it speculative, informational, "
        "a best-practice issue without exploitability, or not a real security bug?\n"
        "3. If it is a real vulnerability, could a correct PoC trigger an AddressSanitizer "
        "(ASAN) crash? Consider what memory operations are involved.\n"
        "4. What are the most relevant CWE IDs (e.g. CWE-476, CWE-125)? List at most 3.\n\n"
        "First write your reasoning, then output your final judgement as a JSON block:\n"
        "```json\n"
        '{"is_vulnerability": true|false, "is_asan": true|false, '
        '"cwe_ids": ["CWE-XXX", ...], "reason": "one sentence"}\n'
        "```"
    )
    raw = _llm_call(model, [{"role": "user", "content": prompt}], kwargs)
    _, json_str = _extract_json_block(raw, array=False)
    m = re.search(r"\{[\s\S]*\}", json_str)
    try:
        result = json.loads(m.group(0) if m else raw)
        return {
            "is_vulnerability": bool(result.get("is_vulnerability", False)),
            "is_asan": bool(result.get("is_asan", False)),
            "cwe_ids": [str(c) for c in result.get("cwe_ids", [])],
            "reason": result.get("reason", ""),
        }
    except (json.JSONDecodeError, AttributeError):
        return {"is_vulnerability": False, "is_asan": False, "cwe_ids": [], "reason": f"parse error: {raw[:200]}"}


# ===========================================================================
# Stage 2b: LLM-based dedup
# ===========================================================================


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


def _llm_same_vuln(hyp_a: dict, hyp_b: dict, model: str, kwargs: dict) -> bool:
    """Ask the LLM whether two hypotheses describe the same vulnerability."""
    ha = hyp_a.get("hypothesis", hyp_a)
    hb = hyp_b.get("hypothesis", hyp_b)
    prompt = (
        "You are a security expert. Determine whether the following two vulnerability "
        "hypotheses describe the SAME underlying vulnerability (just phrased differently "
        "or focusing on different aspects of the same bug), or whether they are genuinely "
        "DIFFERENT vulnerabilities.\n\n"
        f"## Hypothesis A\n"
        f"Summary: {ha.get('summary', '')}\n"
        f"Function: {ha.get('function', '')}\n"
        f"Description: {ha.get('description', '') or ha.get('context', '')}\n\n"
        f"## Hypothesis B\n"
        f"Summary: {hb.get('summary', '')}\n"
        f"Function: {hb.get('function', '')}\n"
        f"Description: {hb.get('description', '') or hb.get('context', '')}\n\n"
        "Think step by step:\n"
        "1. What is the root cause described in Hypothesis A?\n"
        "2. What is the root cause described in Hypothesis B?\n"
        "3. Are these the same root cause, or genuinely different bugs?\n\n"
        "First write your reasoning, then output your final judgement as a JSON block:\n"
        "```json\n"
        '{"same_vulnerability": true or false, "reason": "one sentence"}\n'
        "```"
    )
    raw = _llm_call(model, [{"role": "user", "content": prompt}], kwargs)
    _, json_str = _extract_json_block(raw, array=False)
    m = re.search(r"\{[\s\S]*\}", json_str)
    try:
        result = json.loads(m.group(0) if m else raw)
        return bool(result.get("same_vulnerability", False))
    except (json.JSONDecodeError, AttributeError):
        return False


class _UnionFind:
    def __init__(self, n: int):
        self.parent = list(range(n))

    def find(self, x: int) -> int:
        while self.parent[x] != x:
            self.parent[x] = self.parent[self.parent[x]]
            x = self.parent[x]
        return x

    def union(self, x: int, y: int) -> None:
        self.parent[self.find(x)] = self.find(y)


def dedup_hypotheses(
    hypotheses: list[dict],
    cwe_map: dict[int, list[str]],
    model: str,
    kwargs: dict,
    workers: int = 8,
) -> tuple[list[dict], list[dict]]:
    """Dedup hypotheses using LLM judgement.

    Only pairs with overlapping lines AND at least one shared CWE are candidates.
    For each candidate pair, ask the LLM if they are the same vulnerability.
    Merge confirmed duplicates via union-find, keep the one with the most hotspots.

    Returns (kept, removed).
    """
    n = len(hypotheses)
    if n <= 1:
        return list(hypotheses), []

    hs_cache = [_hotspots(h) for h in hypotheses]

    # Find candidate pairs: overlapping lines + shared CWE
    candidate_pairs: list[tuple[int, int]] = []
    for i in range(n):
        for j in range(i + 1, n):
            if not _line_overlap(hs_cache[i], hs_cache[j]):
                continue
            cwes_i = set(cwe_map.get(i, []))
            cwes_j = set(cwe_map.get(j, []))
            if cwes_i & cwes_j:
                candidate_pairs.append((i, j))

    if not candidate_pairs:
        return list(hypotheses), []

    print(f"    {len(candidate_pairs)} candidate pairs for LLM dedup...", file=sys.stderr)

    # Query LLM for each candidate pair in parallel
    merge_decisions: dict[tuple[int, int], bool] = {}
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {
            pool.submit(_llm_same_vuln, hypotheses[i], hypotheses[j], model, kwargs): (i, j)
            for i, j in candidate_pairs
        }
        for future in as_completed(futures):
            pair = futures[future]
            try:
                merge_decisions[pair] = future.result()
            except Exception:
                merge_decisions[pair] = False

    # Union-find on confirmed duplicates
    uf = _UnionFind(n)
    for (i, j), is_same in merge_decisions.items():
        if is_same:
            uf.union(i, j)

    from collections import defaultdict
    groups: dict[int, list[int]] = defaultdict(list)
    for i in range(n):
        groups[uf.find(i)].append(i)

    kept, removed = [], []
    for members in sorted(groups.values(), key=lambda g: g[0]):
        best = max(members, key=lambda i: len(hs_cache[i]))
        kept.append(hypotheses[best])
        for idx in members:
            if idx != best:
                entry = dict(hypotheses[idx])
                best_summary = hypotheses[best].get("hypothesis", hypotheses[best]).get("summary", "")
                entry["_removed"] = f"Duplicate of '{best_summary[:80]}' (LLM-confirmed)"
                removed.append(entry)

    return kept, removed


# ===========================================================================
# Stage 3: Docker sub-agent filtering
# ===========================================================================

FILTER_AGENT_SYSTEM = """\
You are a vulnerability verification agent. You have access to a bash shell inside a Docker \
container containing the full repository source code.

You will be given a vulnerability hypothesis. Your job is to carefully inspect the code to \
determine whether the hypothesis is VALID or INVALID.

A hypothesis is INVALID if:
- The code path is unreachable from any entry point
- The supposed vulnerable condition is always prevented by an earlier check
- The variable/buffer is always properly bounded before the alleged overflow
- The hypothesis misreads the code logic (e.g., confuses a safe pattern for an unsafe one)
- The described preconditions are impossible to satisfy simultaneously

A hypothesis is VALID (or at least PLAUSIBLE) if:
- The described code path is reachable
- The preconditions are satisfiable
- The alleged missing check or overflow is genuinely present in the code
- You cannot definitively prove it wrong

Be conservative: if you are unsure, mark it as VALID.

You interact by calling tools. Every response MUST include BOTH:
1. A brief description of your observation and next step.
2. Exactly ONE tool call — either `bash` or `finish`.

IMPORTANT: You only have {{max_rounds}} rounds (tool calls) to complete your verification. \
Plan your investigation carefully and call `finish` before you run out of rounds.

When done, call the `finish` tool with:
- status: 'success'
- analysis: your reasoning
- payload: {"verdict": "VALID" or "INVALID", "confidence": 0.0-1.0, "reason": "explanation"}
"""


FILTER_AGENT_INSTANCE = """\
The repository is located at {{project_path}}.
The target file is: {{target_file}}

## Hypothesis to verify

**Summary:** {{hypothesis_summary}}
{% if hypothesis_description %}**Description:** {{hypothesis_description}}{% endif %}
{% if hypothesis_function %}**Function:** {{hypothesis_function}}{% endif %}
{% if hypothesis_trigger %}**Trigger:** {{hypothesis_trigger}}{% endif %}
{% if hypothesis_expected_crash %}**Expected crash:** {{hypothesis_expected_crash}}{% endif %}

{% if hotspots %}
## Hotspot Locations
{% for hs in hotspots %}- {{hs.file_path}}:{{hs.line_start}}-{{hs.line_end}} ({{hs.function}}): {{hs.context}}
{% endfor %}{% endif %}

## Instructions
You have **{{max_rounds}} rounds** to complete your verification. Plan wisely.

1. Read the relevant source code around the hotspots
2. Trace callers/callees to understand reachability
3. Check if the preconditions are satisfiable
4. Check if any earlier bounds checks prevent the vulnerability
5. Call `finish` with your verdict

Rules:
- Do NOT compile or run the code. Static analysis only.
- Do NOT modify any files.
- Use `grep`, `cat`, `head`, `tail`, etc. to inspect code.
"""


def _copy_repo_into_container(env: Any, repo_path: Path, destination: Path) -> None:
    """Stream repo via tar into running container."""
    archive_cmd = [
        "tar", "-C", str(repo_path.parent), "-cf", "-", repo_path.name,
    ]
    extract_cmd = (
        f"mkdir -p {destination} && rm -rf {destination}/* && "
        f"tar -C {destination} --strip-components=1 -xf -"
    )
    with subprocess.Popen(archive_cmd, stdout=subprocess.PIPE) as tar_proc:
        exec_cmd = [
            env.config.executable, "exec", "-i", env.container_id,
            "bash", "-lc", extract_cmd,
        ]
        subprocess.run(exec_cmd, stdin=tar_proc.stdout, check=True, timeout=120)
        tar_proc.wait()
        if tar_proc.returncode != 0:
            raise RuntimeError("Failed to archive repo for container copy")


def _run_filter_agent(
    hyp: dict,
    repo_path: Path,
    target_file: str,
    model_name: str,
    model_config: dict,
    docker_image: str,
    agent_step_limit: int,
    agent_cost_limit: float,
    docker_timeout: int,
) -> dict:
    """Spin up a Docker container, run a DefaultAgent to verify one hypothesis, clean up.

    Returns dict with verdict, confidence, reason, reasoning, error.
    """
    from vulagent.agents.default import DefaultAgent, AgentConfig
    from vulagent.environments.docker import DockerEnvironment
    from vulagent.models import get_model

    h = hyp.get("hypothesis", hyp)
    hotspots = h.get("hotspots", [])
    project_path = "/src"

    env = None
    try:
        env = DockerEnvironment(
            image=docker_image,
            cwd=project_path,
            run_args=["--rm"],
            timeout=docker_timeout,
        )
        _copy_repo_into_container(env, repo_path, Path(project_path))
        env.config.env.update({"PAGER": "cat", "LESS": "-R"})

        model = get_model(model_name, model_config)
        agent = DefaultAgent(
            model, env,
            system_template=FILTER_AGENT_SYSTEM,
            instance_template=FILTER_AGENT_INSTANCE,
            format_error_template=(
                "Your last response did not include a tool call. "
                "Every response MUST contain exactly one tool call: `bash` or `finish`."
            ),
            action_observation_template=(
                "<returncode>{{output.returncode}}</returncode>\n"
                "{% if output.output | length < 8000 %}"
                "<output>\n{{ output.output }}</output>"
                "{% else %}"
                "<output_head>\n{{ output.output[:4000] }}\n</output_head>\n"
                "<elided>{{ output.output | length - 8000 }} chars</elided>\n"
                "<output_tail>\n{{ output.output[-4000:] }}\n</output_tail>"
                "{% endif %}"
            ),
            step_limit=agent_step_limit,
            cost_limit=agent_cost_limit,
        )

        exit_status, result_text = agent.run(
            "Verify the vulnerability hypothesis",
            project_path=project_path,
            target_file=target_file,
            max_rounds=agent_step_limit,
            hypothesis_summary=h.get("summary", ""),
            hypothesis_description=h.get("description", ""),
            hypothesis_function=h.get("function", ""),
            hypothesis_trigger=h.get("trigger", ""),
            hypothesis_expected_crash=h.get("expected_crash", ""),
            hotspots=hotspots,
        )

        trajectory = agent.messages

        # Parse the finish payload
        try:
            import yaml
            parsed = yaml.safe_load(result_text)
            if isinstance(parsed, dict):
                payload = parsed.get("payload", parsed)
                return {
                    "verdict": str(payload.get("verdict", "VALID")).upper(),
                    "confidence": float(payload.get("confidence", 0.5)),
                    "reason": payload.get("reason", ""),
                    "reasoning": parsed.get("analysis", ""),
                    "exit_status": exit_status,
                    "model_cost": agent.model.cost,
                    "model_calls": agent.model.n_calls,
                    "trajectory": trajectory,
                    "error": None,
                }
        except Exception:
            pass

        # Fallback: try to extract JSON from result_text
        _, json_str = _extract_json_block(result_text, array=False)
        try:
            data = json.loads(json_str)
            return {
                "verdict": str(data.get("verdict", "VALID")).upper(),
                "confidence": float(data.get("confidence", 0.5)),
                "reason": data.get("reason", ""),
                "reasoning": result_text,
                "exit_status": exit_status,
                "model_cost": getattr(agent.model, "cost", 0),
                "model_calls": getattr(agent.model, "n_calls", 0),
                "trajectory": trajectory,
                "error": None,
            }
        except json.JSONDecodeError:
            return {
                "verdict": "VALID",
                "confidence": 0.0,
                "reason": "Could not parse agent output",
                "reasoning": result_text,
                "exit_status": exit_status,
                "model_cost": getattr(agent.model, "cost", 0),
                "model_calls": getattr(agent.model, "n_calls", 0),
                "trajectory": trajectory,
                "error": f"parse error: {result_text[:200]}",
            }

    except Exception as e:
        return {
            "verdict": "VALID",  # conservative
            "confidence": 0.0,
            "reason": str(e),
            "reasoning": "",
            "exit_status": "Error",
            "model_cost": 0,
            "model_calls": 0,
            "trajectory": [],
            "error": str(e),
        }
    finally:
        if env is not None:
            env.cleanup()


# ===========================================================================
# Pipeline orchestration
# ===========================================================================


def run_pipeline(
    file_path: Path,
    repo_path: Path,
    model_name: str,
    model_kwargs: dict,
    filter_model: str | None = None,
    filter_model_kwargs: dict | None = None,
    workers: int = 4,
    max_functions: int = 50,
    filter_workers: int = 4,
    docker_image: str = "ubuntu:22.04",
    agent_step_limit: int = 5,
    agent_cost_limit: float = 2.0,
    docker_timeout: int = 120,
) -> dict:
    """Run the full scan-and-filter pipeline. Returns the result dict."""

    assert file_path.is_relative_to(repo_path), f"{file_path} is not under {repo_path}"

    source = file_path.read_text(errors="replace")
    started_at = datetime.now(timezone.utc)

    # -------------------------------------------------------------------
    # Stage 1: Hypothesis Generation
    # -------------------------------------------------------------------
    print("\n=== Stage 1: Hypothesis Generation ===", file=sys.stderr)

    print("  Summarizing file...", file=sys.stderr)
    summary, deep_summary, summary_msgs = phase_summarize(model_name, file_path, source, model_kwargs)
    print(f"  Summary: {len(summary)} chars, deep: {len(deep_summary)} chars", file=sys.stderr)

    print("  Parsing functions...", file=sys.stderr)
    functions = parse_functions(file_path, source)
    total_found = len(functions)
    if total_found > max_functions:
        functions = functions[:max_functions]
    print(f"  Found {total_found} functions (using {len(functions)})", file=sys.stderr)

    batches = _make_batches(functions)
    total_tasks = 1 + len(FOCUSED_PASSES) + len(batches)
    effective_workers = min(workers, total_tasks)
    print(
        f"  Running {total_tasks} analysis tasks "
        f"(1 whole-file + {len(FOCUSED_PASSES)} focused + {len(batches)} batches) "
        f"with {effective_workers} workers...",
        file=sys.stderr,
    )

    wholefile_result: dict = {}
    focused_results: list[dict] = [{} for _ in FOCUSED_PASSES]
    function_analyses: list[dict] = [{}] * len(batches)
    completed = 0

    with ThreadPoolExecutor(max_workers=effective_workers) as executor:
        futures: dict = {}
        futures[executor.submit(
            phase_analyze_wholefile, model_name, file_path, summary_msgs, model_kwargs
        )] = ("wholefile", None)
        for idx, prompt in enumerate(FOCUSED_PASSES):
            futures[executor.submit(
                phase_analyze_focused, model_name, file_path, summary_msgs, prompt, model_kwargs
            )] = ("focused", idx)
        for idx, batch in enumerate(batches):
            futures[executor.submit(
                phase_analyze_functions, model_name, file_path, batch, summary_msgs, model_kwargs
            )] = ("batch", idx)

        for future in as_completed(futures):
            kind, idx = futures[future]
            completed += 1
            try:
                result = future.result()
                if kind == "wholefile":
                    wholefile_result = result
                elif kind == "focused":
                    focused_results[idx] = result
                else:
                    function_analyses[idx] = result
                print(f"  [{completed}/{total_tasks}] {kind} done", file=sys.stderr)
            except Exception as e:
                print(f"  [{completed}/{total_tasks}] ERROR ({kind}): {e}", file=sys.stderr)

    all_hypotheses = aggregate_hypotheses(wholefile_result, focused_results, function_analyses)
    print(f"\n  Generated {len(all_hypotheses)} raw hypotheses", file=sys.stderr)

    if not all_hypotheses:
        return _build_result(
            file_path, model_name, started_at,
            total_found, len(function_analyses),
            summary, deep_summary,
            all_hypotheses, [], [],
            wholefile_result, focused_results, function_analyses,
        )

    # -------------------------------------------------------------------
    # Stage 2: Classification & Dedup
    # -------------------------------------------------------------------
    print("\n=== Stage 2: Classification & Filtering ===", file=sys.stderr)

    source_lines = source.splitlines()
    dedup_kwargs = dict(model_kwargs)
    dedup_kwargs["temperature"] = 0.0

    print(f"  Classifying {len(all_hypotheses)} hypotheses...", file=sys.stderr)

    classifications: dict[int, dict] = {}
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {
            pool.submit(classify_hypothesis, h, model_name, dedup_kwargs, source_lines): i
            for i, h in enumerate(all_hypotheses)
        }
        done = 0
        for future in as_completed(futures):
            idx = futures[future]
            done += 1
            try:
                classifications[idx] = future.result()
                is_vuln = classifications[idx]["is_vulnerability"]
                is_asan = classifications[idx]["is_asan"]
                print(
                    f"  [{done}/{len(all_hypotheses)}] "
                    f"{('ASAN' if is_asan else 'VUL') if is_vuln else 'NOT'} — "
                    f"{classifications[idx]['reason'][:70]}",
                    file=sys.stderr,
                )
            except Exception as e:
                classifications[idx] = {
                    "is_vulnerability": False, "is_asan": False, "cwe_ids": [], "reason": f"error: {e}"
                }

    # Filter: keep only ASAN-triggerable vulnerabilities
    valid_indices = [
        i for i in range(len(all_hypotheses))
        if classifications[i]["is_vulnerability"] and classifications[i]["is_asan"]
    ]
    print(
        f"  Filtered: {len(all_hypotheses) - len(valid_indices)} non-asan-vulnerabilities, "
        f"{len(valid_indices)} remain",
        file=sys.stderr,
    )

    for i, h in enumerate(all_hypotheses):
        h["_cwe_ids"] = classifications[i]["cwe_ids"]
        h["_is_vulnerability"] = classifications[i]["is_vulnerability"]
        h["_is_asan"] = classifications[i]["is_asan"]
        if not classifications[i]["is_vulnerability"]:
            h["_removed"] = f"Not a vulnerability: {classifications[i]['reason']}"
        elif not classifications[i]["is_asan"]:
            h["_removed"] = f"Not ASAN-triggerable: {classifications[i]['reason']}"

    valid_hyps = [all_hypotheses[i] for i in valid_indices]
    cwe_map = {j: classifications[valid_indices[j]]["cwe_ids"] for j in range(len(valid_indices))}

    dedup_kwargs = dict(model_kwargs)
    dedup_kwargs["temperature"] = 0.0
    kept, removed = dedup_hypotheses(valid_hyps, cwe_map, model_name, dedup_kwargs, workers=workers)
    print(f"  Dedup: {len(valid_hyps)} -> {len(kept)} (removed {len(removed)} duplicates)", file=sys.stderr)

    # Mark dedup removals in all_hypotheses
    removed_summaries = {
        r.get("hypothesis", r).get("summary", ""): r.get("_removed", "")
        for r in removed
    }
    for h in all_hypotheses:
        if h.get("_is_vulnerability") and h.get("_is_asan") and not h.get("_removed"):
            summary_text = h.get("hypothesis", h).get("summary", "")
            if summary_text in removed_summaries:
                h["_removed"] = removed_summaries[summary_text]

    if not kept:
        return _build_result(
            file_path, model_name, started_at,
            total_found, len(function_analyses),
            summary, deep_summary,
            all_hypotheses, kept, [],
            wholefile_result, focused_results, function_analyses,
        )

    # -------------------------------------------------------------------
    # Stage 3: Docker Sub-agent Filtering
    # -------------------------------------------------------------------
    print(f"\n=== Stage 3: Docker Sub-agent Filtering ({len(kept)} hypotheses) ===", file=sys.stderr)

    fmodel = filter_model or model_name
    fmodel_config = filter_model_kwargs or {}

    target_file_rel = str(file_path.relative_to(repo_path)) if file_path.is_relative_to(repo_path) else str(file_path)

    print(f"  Filter model: {fmodel}", file=sys.stderr)
    print(f"  Docker image: {docker_image}", file=sys.stderr)
    print(f"  Filter workers: {filter_workers}", file=sys.stderr)
    print(f"  Agent step limit: {agent_step_limit}, cost limit: ${agent_cost_limit}", file=sys.stderr)

    filter_results: dict[int, dict] = {}
    with ThreadPoolExecutor(max_workers=filter_workers) as pool:
        futures = {
            pool.submit(
                _run_filter_agent,
                h, repo_path, target_file_rel,
                fmodel, fmodel_config, docker_image,
                agent_step_limit, agent_cost_limit, docker_timeout,
            ): i
            for i, h in enumerate(kept)
        }
        done = 0
        for future in as_completed(futures):
            idx = futures[future]
            done += 1
            try:
                filter_results[idx] = future.result()
                v = filter_results[idx]
                verdict = v["verdict"]
                conf = v["confidence"]
                reason = v["reason"][:60]
                cost = v.get("model_cost", 0)
                print(
                    f"  [{done}/{len(kept)}] {verdict} (conf={conf:.2f}, ${cost:.3f}) — {reason}",
                    file=sys.stderr,
                )
            except Exception as e:
                filter_results[idx] = {
                    "verdict": "VALID",
                    "confidence": 0.0,
                    "reason": str(e),
                    "reasoning": "",
                    "error": str(e),
                }

    # Apply filter results
    final_hypotheses = []
    for i, h in enumerate(kept):
        fr = filter_results.get(i, {})
        h["_filter_verdict"] = fr.get("verdict", "VALID")
        h["_filter_confidence"] = fr.get("confidence", 0.0)
        h["_filter_reason"] = fr.get("reason", "")
        h["_filter_reasoning"] = fr.get("reasoning", "")
        h["_filter_model_cost"] = fr.get("model_cost", 0)
        h["_filter_model_calls"] = fr.get("model_calls", 0)
        h["_filter_trajectory"] = fr.get("trajectory", [])

        if fr.get("verdict") == "INVALID" and fr.get("confidence", 0) >= 0.7:
            h["_removed"] = f"Filtered by sub-agent: {fr.get('reason', '')}"
            summary_text = h.get("hypothesis", h).get("summary", "")
            for ah in all_hypotheses:
                if ah.get("hypothesis", ah).get("summary", "") == summary_text and not ah.get("_removed"):
                    ah["_removed"] = h["_removed"]
        else:
            final_hypotheses.append(h)

    filtered_out = len(kept) - len(final_hypotheses)
    print(
        f"\n  Sub-agent filter: {len(kept)} -> {len(final_hypotheses)} "
        f"(removed {filtered_out} invalid)",
        file=sys.stderr,
    )

    return _build_result(
        file_path, model_name, started_at,
        total_found, len(function_analyses),
        summary, deep_summary,
        all_hypotheses, kept, final_hypotheses,
        wholefile_result, focused_results, function_analyses,
    )


def _build_result(
    file_path: Path,
    model_name: str,
    started_at: datetime,
    functions_found: int,
    functions_analyzed: int,
    summary: str,
    deep_summary: str,
    all_hypotheses: list[dict],
    deduped_hypotheses: list[dict],
    final_hypotheses: list[dict],
    wholefile_result: dict | None = None,
    focused_results: list[dict] | None = None,
    function_analyses: list[dict] | None = None,
) -> dict:
    """Build the in-memory result dict (used by run_pipeline)."""
    finished_at = datetime.now(timezone.utc)
    return {
        "info": {
            "file_path": str(file_path),
            "model": model_name,
            "started_at_utc": started_at.isoformat(),
            "finished_at_utc": finished_at.isoformat(),
            "duration_seconds": (finished_at - started_at).total_seconds(),
            "functions_found": functions_found,
            "functions_analyzed": functions_analyzed,
            "raw_hypothesis_count": len(all_hypotheses),
            "deduped_hypothesis_count": len(deduped_hypotheses),
            "final_hypothesis_count": len(final_hypotheses),
        },
        "summary": summary,
        "deep_summary": deep_summary,
        "all_hypotheses": all_hypotheses,
        "deduped_hypotheses": deduped_hypotheses,
        "final_hypotheses": final_hypotheses,
        "wholefile_analysis": (wholefile_result or {}).get("analysis", ""),
        "focused_analyses": [
            {k: v for k, v in fr.items() if k != "messages"}
            for fr in (focused_results or [])
        ],
        "function_analyses": [
            {k: v for k, v in fa.items() if not k.startswith("messages_")}
            for fa in (function_analyses or [])
        ],
    }


def _hypothesis_slug(hyp: dict, index: int) -> str:
    """Generate a short filesystem-safe folder name for a hypothesis."""
    h = hyp.get("hypothesis", hyp)
    summary = h.get("summary", "") or h.get("title", "") or f"hypothesis_{index}"
    # Sanitize: lowercase, replace non-alnum with underscore, truncate
    slug = re.sub(r"[^a-z0-9]+", "_", summary.lower()).strip("_")[:80]
    return f"H{index:02d}_{slug}"


def _save_hypothesis_dir(
    base_dir: Path,
    hyp: dict,
    index: int,
) -> None:
    """Write a hypothesis to its own directory with separate trajectory file."""
    slug = _hypothesis_slug(hyp, index)
    hyp_dir = base_dir / slug
    hyp_dir.mkdir(parents=True, exist_ok=True)

    # Extract trajectory before writing hypothesis JSON
    trajectory = hyp.pop("_filter_trajectory", [])

    # Write hypothesis metadata (without trajectory)
    (hyp_dir / "hypothesis.json").write_text(json.dumps(hyp, indent=2))

    # Write trajectory separately if present
    if trajectory:
        (hyp_dir / "filter_trajectory.json").write_text(json.dumps(trajectory, indent=2))

    # Restore trajectory on the dict (in case caller still needs it)
    hyp["_filter_trajectory"] = trajectory


def _save_output(
    output_dir: Path,
    file_path: Path,
    model_name: str,
    started_at: datetime,
    functions_found: int,
    functions_analyzed: int,
    summary: str,
    deep_summary: str,
    all_hypotheses: list[dict],
    deduped_hypotheses: list[dict],
    final_hypotheses: list[dict],
    wholefile_result: dict | None = None,
    focused_results: list[dict] | None = None,
    function_analyses: list[dict] | None = None,
) -> None:
    """Save pipeline output as a directory tree:

    output_dir/
      summary.json          # run info, summaries, analysis metadata
      valid_hypotheses/     # hypotheses that passed all filters
        H00_slug/
          hypothesis.json
          filter_trajectory.json
        H01_slug/
          ...
      invalid_hypotheses/   # hypotheses removed at any stage
        H00_slug/
          hypothesis.json
          filter_trajectory.json  (if it reached stage 3)
        ...
    """
    output_dir.mkdir(parents=True, exist_ok=True)

    finished_at = datetime.now(timezone.utc)

    # Build the set of final hypothesis summaries for partitioning
    final_summaries = {
        h.get("hypothesis", h).get("summary", "") for h in final_hypotheses
    }

    # Write valid hypotheses
    valid_dir = output_dir / "valid_hypotheses"
    valid_dir.mkdir(exist_ok=True)
    for i, h in enumerate(final_hypotheses):
        _save_hypothesis_dir(valid_dir, h, i)

    # Write invalid hypotheses (everything in all_hypotheses that has _removed,
    # plus deduped ones that didn't make it to final)
    invalid_dir = output_dir / "invalid_hypotheses"
    invalid_dir.mkdir(exist_ok=True)
    invalid_index = 0
    seen_summaries: set[str] = set()
    for h in all_hypotheses:
        hyp_summary = h.get("hypothesis", h).get("summary", "")
        if hyp_summary in seen_summaries:
            continue
        if h.get("_removed") or hyp_summary not in final_summaries:
            _save_hypothesis_dir(invalid_dir, h, invalid_index)
            invalid_index += 1
            seen_summaries.add(hyp_summary)

    # Write summary.json (lightweight, no trajectories, no full hypothesis lists)
    summary_data = {
        "info": {
            "file_path": str(file_path),
            "model": model_name,
            "started_at_utc": started_at.isoformat(),
            "finished_at_utc": finished_at.isoformat(),
            "duration_seconds": (finished_at - started_at).total_seconds(),
            "functions_found": functions_found,
            "functions_analyzed": functions_analyzed,
            "raw_hypothesis_count": len(all_hypotheses),
            "deduped_hypothesis_count": len(deduped_hypotheses),
            "final_hypothesis_count": len(final_hypotheses),
        },
        "summary": summary,
        "deep_summary": deep_summary,
        "wholefile_analysis": (wholefile_result or {}).get("analysis", ""),
        "focused_analyses": [
            {k: v for k, v in fr.items() if k != "messages"}
            for fr in (focused_results or [])
        ],
        "function_analyses": [
            {k: v for k, v in fa.items() if not k.startswith("messages_")}
            for fa in (function_analyses or [])
        ],
        "valid_hypotheses": [
            h.get("hypothesis", h).get("summary", "") for h in final_hypotheses
        ],
        "invalid_hypothesis_count": invalid_index,
    }
    (output_dir / "summary.json").write_text(json.dumps(summary_data, indent=2))


# ===========================================================================
# CLI
# ===========================================================================


def main():
    parser = argparse.ArgumentParser(
        description="Scan-and-filter: hypothesize -> dedup -> Docker sub-agent filter"
    )
    parser.add_argument("-f", "--file", required=True, help="Source file to analyze")
    parser.add_argument("-r", "--repo", default=None,
                        help="Repository root (default: parent dir of --file)")
    parser.add_argument("-m", "--model", default=os.getenv("MSWEA_MODEL_NAME"),
                        help="Model for hypothesis generation & dedup")
    parser.add_argument("-b", "--base-url", default=None, help="LiteLLM proxy base URL")
    parser.add_argument("-k", "--api-key", default=os.getenv("MSWEA_MODEL_API_KEY"), help="API key")
    parser.add_argument("-o", "--output", default=None, help="Output JSON path")

    parser.add_argument("--filter-model", default=None,
                        help="Model for Docker sub-agent filtering (default: same as --model)")
    parser.add_argument("--filter-base-url", default=None,
                        help="Base URL for filter model (default: same as --base-url)")
    parser.add_argument("--filter-api-key", default=None,
                        help="API key for filter model (default: same as --api-key)")

    parser.add_argument("--docker-image", default="ubuntu:22.04",
                        help="Docker image for sub-agent containers (default: ubuntu:22.04)")
    parser.add_argument("--agent-step-limit", type=int, default=5,
                        help="Max steps per filter sub-agent (default: 5)")
    parser.add_argument("--agent-cost-limit", type=float, default=2.0,
                        help="Max cost per filter sub-agent (default: $2.00)")
    parser.add_argument("--docker-timeout", type=int, default=120,
                        help="Timeout in seconds for Docker commands (default: 120)")

    parser.add_argument("--workers", type=int, default=4,
                        help="Parallel workers for hypothesis generation (default: 4)")
    parser.add_argument("--filter-workers", type=int, default=4,
                        help="Parallel Docker sub-agent workers (default: 4)")
    parser.add_argument("--max-functions", type=int, default=50,
                        help="Max functions to analyze (default: 50)")
    args = parser.parse_args()

    file_path = Path(args.file).resolve()
    if not file_path.is_file():
        print(f"Error: file not found: {file_path}", file=sys.stderr)
        sys.exit(1)

    repo_path = Path(args.repo).resolve() if args.repo else file_path.parent
    if not repo_path.is_dir():
        print(f"Error: repo not found: {repo_path}", file=sys.stderr)
        sys.exit(1)

    model_name = args.model
    if not model_name:
        print("Error: no model specified. Use --model or set MSWEA_MODEL_NAME.", file=sys.stderr)
        sys.exit(1)

    if args.output:
        output_dir = Path(args.output)
    else:
        ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
        output_dir = Path("output/scan_and_filter") / f"saf_{file_path.stem}_{ts}"
    output_dir.mkdir(parents=True, exist_ok=True)

    model_kwargs: dict = {"temperature": 1.0, "drop_params": True}
    if args.base_url:
        model_kwargs["base_url"] = args.base_url
    if args.api_key:
        model_kwargs["api_key"] = args.api_key

    filter_model_kwargs: dict = {"model_kwargs": {"drop_params": True}}
    if args.filter_base_url or args.base_url:
        filter_model_kwargs["model_kwargs"]["base_url"] = args.filter_base_url or args.base_url
    if args.filter_api_key or args.api_key:
        filter_model_kwargs["model_kwargs"]["api_key"] = args.filter_api_key or args.api_key

    print(f"File:         {file_path}")
    print(f"Repo:         {repo_path}")
    print(f"Model:        {model_name}")
    print(f"Filter model: {args.filter_model or model_name}")
    print(f"Docker image: {args.docker_image}")
    print(f"Output:       {output_dir}")

    result = run_pipeline(
        file_path=file_path,
        repo_path=repo_path,
        model_name=model_name,
        model_kwargs=model_kwargs,
        filter_model=args.filter_model,
        filter_model_kwargs=filter_model_kwargs,
        workers=args.workers,
        max_functions=args.max_functions,
        filter_workers=args.filter_workers,
        docker_image=args.docker_image,
        agent_step_limit=args.agent_step_limit,
        agent_cost_limit=args.agent_cost_limit,
        docker_timeout=args.docker_timeout,
    )

    _save_output(
        output_dir=output_dir,
        file_path=file_path,
        model_name=model_name,
        started_at=datetime.fromisoformat(result["info"]["started_at_utc"]),
        functions_found=result["info"]["functions_found"],
        functions_analyzed=result["info"]["functions_analyzed"],
        summary=result["summary"],
        deep_summary=result["deep_summary"],
        all_hypotheses=result["all_hypotheses"],
        deduped_hypotheses=result["deduped_hypotheses"],
        final_hypotheses=result["final_hypotheses"],
    )
    print(f"\nSaved to: {output_dir}")
    info = result["info"]
    print(
        f"Pipeline: {info['raw_hypothesis_count']} raw -> "
        f"{info['deduped_hypothesis_count']} deduped -> "
        f"{info['final_hypothesis_count']} final "
        f"({info['duration_seconds']:.1f}s)"
    )
    valid_count = len(list((output_dir / "valid_hypotheses").iterdir()))
    invalid_count = len(list((output_dir / "invalid_hypotheses").iterdir()))
    print(f"  valid_hypotheses/   ({valid_count} entries)")
    print(f"  invalid_hypotheses/ ({invalid_count} entries)")


if __name__ == "__main__":
    main()
