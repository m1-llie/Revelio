"""Extracted pure functions for the scan-and-filter pipeline.

Contains:
- LLM helpers (litellm wrappers)
- Tree-sitter function parsing
- Stage 1: Multi-pass hypothesis generation phases
- Stage 2: Classification & dedup
- Stage 3: Docker sub-agent filter templates & runner
"""

from __future__ import annotations

import json
import logging
import re
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import litellm

litellm.disable_cache()

logger = logging.getLogger("scan_filter_stages")


# ===========================================================================
# LLM helpers
# ===========================================================================


class CostTracker:
    """Thread-safe accumulator for LLM cost and call counts."""

    def __init__(self) -> None:
        self.cost = 0.0
        self.calls = 0
        self._lock = threading.Lock()

    def add(self, cost: float, calls: int = 1) -> None:
        with self._lock:
            self.cost += cost
            self.calls += calls

    def snapshot(self) -> tuple[float, int]:
        with self._lock:
            return self.cost, self.calls


def _calc_cost(resp: Any) -> float:
    """Extract cost from a litellm response, returning 0.0 on failure."""
    try:
        return litellm.cost_calculator.completion_cost(resp)
    except Exception:
        return 0.0


def llm_call(
    model: str, messages: list[dict], kwargs: dict,
    cost_tracker: CostTracker | None = None,
) -> str:
    """Call LLM with retry on rate limits. Optionally accumulates cost."""
    max_retries, base_delay = 8, 5.0
    for attempt in range(max_retries):
        try:
            resp = litellm.completion(model=model, messages=messages, **kwargs)
            if cost_tracker is not None:
                cost_tracker.add(_calc_cost(resp))
            return resp.choices[0].message.content or ""
        except litellm.RateLimitError:
            if attempt == max_retries - 1:
                raise
            time.sleep(base_delay * (2 ** attempt))
    raise RuntimeError("Unreachable")


def chat_send(
    messages: list[dict], model: str, user_text: str, kwargs: dict,
    cost_tracker: CostTracker | None = None,
) -> str:
    """Append user message, call LLM, append assistant reply, return reply."""
    messages.append({"role": "user", "content": user_text})
    reply = llm_call(model, messages, kwargs, cost_tracker=cost_tracker)
    messages.append({"role": "assistant", "content": reply})
    return reply


def extract_json_block(text: str, array: bool = True) -> tuple[str, str]:
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


def truncate(text: str, max_chars: int = 12_000) -> str:
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


def make_batches(funcs: list[FunctionInfo], short_threshold: int = 100,
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


FOCUSED_PASSES = [
    "Good. Now please re-examine the code under the following assumption: **every pointer can be NULL**. "
    "For each pointer dereference, check whether a NULL value could reach it and what the consequence "
    "would be. Form hypotheses for any potential NULL pointer dereference vulnerabilities you find.",

    "Good. Now please re-examine the code under the following assumption: **every if condition may be "
    "written wrong** — i.e. the branch condition could be written wrong. For each if statement, check "
    "if the branch conditions are written correctly. Form hypotheses for any potential logic errors, "
    "missing checks, or incorrect branch conditions you find.",
]


def _ask_for_json(
    msgs: list[dict], model: str, kwargs: dict,
    cost_tracker: CostTracker | None = None,
) -> tuple[str, list]:
    """Continue conversation asking for hypotheses as JSON. Returns (raw_reply, parsed_list)."""
    reply = chat_send(
        msgs, model,
        "Based on your analysis above, please output a JSON list of hypotheses "
        "following this exact schema (output ONLY valid JSON, no prose before or after):\n\n"
        f"```json\n{HYPOTHESIS_SCHEMA}\n```\n\n"
        "One object per distinct vulnerability hypothesis. "
        "Return an empty list [] if no vulnerabilities were found.",
        kwargs,
        cost_tracker=cost_tracker,
    )
    _, raw_json = extract_json_block(reply, array=True)
    try:
        return reply, json.loads(raw_json)
    except json.JSONDecodeError:
        return reply, []


def phase_summarize(
    model: str, file_path: Path, source: str, kwargs: dict,
    cost_tracker: CostTracker | None = None,
) -> tuple[str, str, list[dict]]:
    msgs: list[dict] = []
    round1 = chat_send(
        msgs, model,
        f"Here is the file `{file_path.name}`:\n\n```\n{truncate(source)}\n```\n\n"
        "Please produce a summary of this file. Note that your summary should explain "
        "**all** of the features and functionalities. Do this by checking whether you "
        "can address every line of the file to one of the features/functionalities.",
        kwargs,
        cost_tracker=cost_tracker,
    )
    round2 = chat_send(msgs, model, "good. now please summarize into more high-level features.", kwargs, cost_tracker=cost_tracker)
    return round1, round2, msgs


def phase_analyze_wholefile(
    model: str, file_path: Path, summary_msgs: list[dict], kwargs: dict,
    cost_tracker: CostTracker | None = None,
) -> dict:
    msgs = list(summary_msgs)
    analysis = chat_send(
        msgs, model,
        "Good. now please refer to your own summarization and form some hypothesis about "
        "feature-related vulnerabilities. Note that you don't have to cover all the "
        "vulnerabilities, just cover **all** of the feature-related ones.\n\n"
        "Please review each feature to form hypothesis. Please think very carefully about "
        "the features. Especially do not miss the vulnerabilities related to uncontrolled "
        "resource consumption.",
        kwargs,
        cost_tracker=cost_tracker,
    )
    _, hypotheses = _ask_for_json(msgs, model, kwargs, cost_tracker=cost_tracker)
    return {"analysis": analysis, "hypotheses": hypotheses, "messages": msgs}


def phase_analyze_focused(
    model: str, file_path: Path, summary_msgs: list[dict],
    focus_prompt: str, kwargs: dict,
    cost_tracker: CostTracker | None = None,
) -> dict:
    msgs = list(summary_msgs)
    analysis = chat_send(msgs, model, focus_prompt, kwargs, cost_tracker=cost_tracker)
    _, hypotheses = _ask_for_json(msgs, model, kwargs, cost_tracker=cost_tracker)
    return {"focus_prompt": focus_prompt, "analysis": analysis, "hypotheses": hypotheses, "messages": msgs}


def phase_analyze_functions(
    model: str, file_path: Path, funcs: list[FunctionInfo],
    summary_msgs: list[dict], kwargs: dict,
    cost_tracker: CostTracker | None = None,
) -> dict:
    combined_snippet = "\n\n".join(
        f"Function `{f.name}` (lines {f.start_line}\u2013{f.end_line}):\n"
        f"```\n{truncate(f.source, 6_000)}\n```"
        for f in funcs
    )
    label = ", ".join(f.name for f in funcs)

    msgs = list(summary_msgs)
    formulation = chat_send(
        msgs, model,
        f"Good. Now please examine the following function(s):\n\n{combined_snippet}\n\n"
        "Please refer to your own summarization and form some hypothesis about potential "
        "vulnerabilities. You should try to cover all the vulnerabilities, both feature-related "
        "and feature-unrelated.\n\n"
        "Please try to find all the vulnerabilities. Especially do not miss the vulnerabilities "
        "related to uncontrolled resource consumption, and more classic vulnerabilities like "
        "wrong if-clause conditions, missed NULL check, and uninitialized variables.",
        kwargs,
        cost_tracker=cost_tracker,
    )
    _, hypotheses = _ask_for_json(msgs, model, kwargs, cost_tracker=cost_tracker)
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
            header = f"Hotspot: {loc} ({fn}) \u2014 {ctx}" if fn else f"Hotspot: {loc} \u2014 {ctx}"
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


def classify_hypothesis(
    hyp: dict, model: str, kwargs: dict,
    source_lines: list[str] | None = None,
    cost_tracker: CostTracker | None = None,
) -> dict:
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
    raw = llm_call(model, [{"role": "user", "content": prompt}], kwargs, cost_tracker=cost_tracker)
    _, json_str = extract_json_block(raw, array=False)
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


def _llm_same_vuln(hyp_a: dict, hyp_b: dict, model: str, kwargs: dict,
                   cost_tracker: CostTracker | None = None) -> bool:
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
    raw = llm_call(model, [{"role": "user", "content": prompt}], kwargs, cost_tracker=cost_tracker)
    _, json_str = extract_json_block(raw, array=False)
    m = re.search(r"\{[\s\S]*\}", json_str)
    try:
        result = json.loads(m.group(0) if m else raw)
        return bool(result.get("same_vulnerability", False))
    except (json.JSONDecodeError, AttributeError):
        return False


class UnionFind:
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
    cost_tracker: CostTracker | None = None,
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

    logger.info("%d candidate pairs for LLM dedup...", len(candidate_pairs))

    merge_decisions: dict[tuple[int, int], bool] = {}
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {
            pool.submit(_llm_same_vuln, hypotheses[i], hypotheses[j], model, kwargs, cost_tracker): (i, j)
            for i, j in candidate_pairs
        }
        for future in as_completed(futures):
            pair = futures[future]
            try:
                merge_decisions[pair] = future.result()
            except Exception:
                merge_decisions[pair] = False

    uf = UnionFind(n)
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

## Budget
You have exactly **{{max_rounds}} tool-call rounds** to complete your verification. \
Plan your investigation carefully:
- Spend the first rounds reading the relevant source at the hotspot locations.
- Trace callers/callees to check reachability and preconditions.
- You will receive an explicit warning when you have 3 rounds left. At that point, \
wrap up your analysis and call `finish` on your next round.

When done, call the `finish` tool with:
- status: 'success'
- analysis: your reasoning
- payload: {"verdict": "VALID" or "INVALID", "confidence": 0.0-1.0, "reason": "one-line explanation"}
"""

FILTER_AGENT_WRAP_UP_WARNING = (
    "⚠️ WARNING: You have only {remaining} rounds left (out of {total}). "
    "You MUST call `finish` within the next {remaining} rounds or your analysis will be cut short. "
    "Wrap up your reasoning now and call `finish` with your verdict, confidence, and reason."
)


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


def _run_agent_with_warning(agent: Any, step_limit: int, warn_at: int = 3, **kwargs) -> tuple[str, str]:
    """Run the agent loop with a wrap-up warning injected when `warn_at` steps remain.

    Replicates DefaultAgent.run() but injects a user-role warning message
    when the remaining step budget hits `warn_at`.
    """
    from vulagent.agents.default import NonTerminatingException, Submitted, TerminatingException

    agent.extra_template_vars |= kwargs
    agent.messages = []
    agent.add_message("system", agent.render_template(agent.config.system_template))
    agent.add_message("user", agent.render_template(agent.config.instance_template))

    steps_used = 0
    warned = False

    while True:
        # Inject wrap-up warning when warn_at steps remain
        remaining = step_limit - steps_used
        if not warned and 0 < remaining <= warn_at:
            warned = True
            agent.add_message(
                "user",
                FILTER_AGENT_WRAP_UP_WARNING.format(remaining=remaining, total=step_limit),
            )

        try:
            agent.step()
            steps_used += 1
        except NonTerminatingException as e:
            agent.add_message("user", str(e))
        except Submitted as e:
            return type(e).__name__, str(e)
        except TerminatingException as e:
            agent.add_message("user", str(e))
            return type(e).__name__, str(e)


def run_filter_agent(
    hyp: dict,
    env: Any,
    target_file: str,
    model_name: str,
    model_config: dict,
    agent_step_limit: int = 20,
    agent_cost_limit: float = 2.0,
) -> dict:
    """Run a DefaultAgent inside the existing Docker container to verify one hypothesis.

    Returns dict with verdict, confidence, reason, reasoning, error.
    """
    from vulagent.agents.default import DefaultAgent
    from vulagent.models import get_model

    h = hyp.get("hypothesis", hyp)
    hotspots = h.get("hotspots", [])
    project_path = env.config.cwd or "/src"

    try:
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

        exit_status, result_text = _run_agent_with_warning(
            agent,
            step_limit=agent_step_limit,
            warn_at=3,
            task="Verify the vulnerability hypothesis",
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
        _, json_str = extract_json_block(result_text, array=False)
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
