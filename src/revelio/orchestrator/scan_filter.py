"""Scan-and-filter orchestrator: multi-pass hypothesis generation, classification/dedup, and sub-agent filtering.

Integrates the scan_and_filter pipeline into the main detect.py workflow.
Reads source files from the Docker container and produces VulnHypotheses
compatible with the downstream PoC/validate/report stages.
"""

from __future__ import annotations

import logging
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any

from revelio.artifacts.schema import CodeReference, VulnHypotheses, VulnHypothesis
from revelio.artifacts.store import ArtifactStore
from revelio.orchestrator.scan_filter_stages import (
    FOCUSED_PASSES,
    CostTracker,
    FunctionInfo,
    aggregate_hypotheses,
    build_unchecked_params_pass,
    classify_hypothesis,
    dedup_hypotheses,
    format_check_analysis_context,
    format_constraint_context,
    hypothesis_priority_key,
    make_batches,
    parse_functions,
    phase_analyze_focused,
    phase_analyze_functions,
    phase_analyze_wholefile,
    phase_summarize,
    run_check_analysis,
    run_constraint_analysis,
    run_filter_agent,
)

logger = logging.getLogger("scan_filter")

DEFAULT_FILE_EXTENSIONS = [".c", ".cpp", ".cc", ".cxx"]

# Directories under /src/ that contain fuzzing infrastructure, not target code.
# These are present in OSS-Fuzz base images and should be skipped.
EXCLUDED_DIRS = {
    "afl", "aflplusplus", "honggfuzz", "libfuzzer", "fuzzer-test-suite",
    "DictFuzzer", "centipede", "fuzztest",
}


def _convert_hypothesis(hyp: dict, index: int, file_path: str) -> VulnHypothesis:
    """Convert a scan_and_filter dict hypothesis to a VulnHypothesis dataclass.

    Propagates triage/dedup metadata (``_severity``/``_primitive``/
    ``_attacker_controls``/``_sanitizers``/``_cwe_ids``) and reachability
    annotation (``_reachable``/``_fuzz_targets``) onto the dataclass so
    downstream ranking can use them.
    """
    h = hyp.get("hypothesis", hyp)
    hotspots = h.get("hotspots", [])
    references = [
        CodeReference(
            file_path=hs.get("file_path", file_path),
            line_start=hs.get("line_start"),
            line_end=hs.get("line_end"),
            function=hs.get("function"),
            context=hs.get("context"),
        )
        for hs in hotspots
    ]
    func = hotspots[0].get("function") if hotspots else None
    warnings = h.get("warnings", [])
    reachable = hyp.get("_reachable")
    return VulnHypothesis(
        hypothesis_id=f"SF{index:02d}",
        title=h.get("summary", "Unknown vulnerability"),
        description=h.get("description") or h.get("summary", ""),
        file_path=file_path,
        function=func,
        trigger=h.get("trigger") or None,
        preconditions=list(h.get("preconditions", [])),
        expected_crash="; ".join(str(w) for w in warnings) if warnings else None,
        confidence=hyp.get("_filter_confidence", 0.5),
        references=references,
        severity=str(hyp.get("_severity", "none")),
        primitive=str(hyp.get("_primitive", "none")),
        attacker_controls=str(hyp.get("_attacker_controls", "none")),
        sanitizers=list(hyp.get("_sanitizers", [])),
        cwe_ids=[str(c) for c in hyp.get("_cwe_ids", [])],
        reachable=(bool(reachable) if reachable is not None else None),
        fuzz_targets=list(hyp.get("_fuzz_targets", [])),
    )


class ScanFilterOrchestrator:
    """Orchestrate the scan-and-filter pipeline inside a Docker container.

    Stages:
    1. Multi-pass hypothesis generation (summarize + whole-file + focused + per-function)
    2. LLM classification & dedup (is_vulnerability, sanitizers{asan,ubsan,msan}, CWE, then LLM dedup)
    3. Docker sub-agent filtering (verify VALID/INVALID via code inspection)
    """

    def __init__(
        self,
        *,
        env: Any,
        model_name: str,
        model_config: dict[str, Any] | None = None,
        store: ArtifactStore,
        log_fn: Any | None = None,
        step_log_fn: Any | None = None,
        file_extensions: list[str] | None = None,
        max_workers: int = 4,
        filter_model: str | None = None,
        filter_model_config: dict[str, Any] | None = None,
        filter_workers: int = 4,
        max_functions: int = 50,
        agent_step_limit: int = 20,
        agent_cost_limit: float = 2.0,
        model_kwargs: dict[str, Any] | None = None,
    ):
        self.env = env
        self.model_name = model_name
        self.model_config = model_config or {}
        self.store = store
        self.log_fn = log_fn
        self.step_log_fn = step_log_fn or log_fn
        self.file_extensions = file_extensions or DEFAULT_FILE_EXTENSIONS
        self.max_workers = max_workers
        self.filter_model = filter_model or model_name
        # Build filter model config for get_model() (used by DefaultAgent in
        # independent static filtering)
        if filter_model_config:
            self.filter_model_config = filter_model_config
        else:
            # Derive from model_kwargs so api_key/base_url are passed through
            fmc: dict[str, Any] = {}
            mkw = model_kwargs or {}
            if mkw.get("api_key"):
                fmc.setdefault("model_kwargs", {})["api_key"] = mkw["api_key"]
            if mkw.get("base_url"):
                fmc.setdefault("model_kwargs", {})["base_url"] = mkw["base_url"]
            self.filter_model_config = fmc
        self.filter_workers = filter_workers
        self.max_functions = max_functions
        self.agent_step_limit = agent_step_limit
        self.agent_cost_limit = agent_cost_limit
        self.model_kwargs = model_kwargs or {"temperature": 1.0, "drop_params": True}
        # Per-function reachability cache: function symbol -> list of fuzz-target
        # binaries whose nm table contains it. ``None`` means lookup failed or
        # the ``arvo`` wrapper doesn't support ``targets`` (non-multi-sanitizer
        # images). Populated lazily by ``_lookup_fuzz_targets``.
        self._reachability_cache: dict[str, list[str] | None] = {}
        # Remember whether ``arvo targets`` is usable in this container. If the
        # first probe fails or returns an error, stop issuing further lookups.
        self._arvo_targets_available: bool | None = None

    def _log(self, message: str) -> None:
        if self.log_fn:
            self.log_fn(message)

    def _lookup_fuzz_targets(self, function: str | None) -> list[str] | None:
        """Return fuzzer binaries whose symbol table contains ``function``.

        Uses the ``arvo targets <symbol>`` nm-based lookup. Returns:
            * ``list[str]`` — matching binaries (possibly empty = unreachable).
            * ``None``      — lookup is not available (original ARVO images,
                              stripped binaries, missing `arvo targets`, etc.).
                              Callers should treat this as "unknown".

        Results are cached per function symbol for the life of this
        orchestrator instance.
        """
        if not function:
            return None
        if self._arvo_targets_available is False:
            return None
        if function in self._reachability_cache:
            return self._reachability_cache[function]

        # Probe once: if `arvo targets` isn't supported, disable further lookups.
        try:
            result = self.env.execute(
                f"arvo targets {function} 2>/dev/null; echo __rc=$?"
            )
        except Exception as e:
            self._log(f"[scan_filter] reachability probe failed: {e}")
            self._arvo_targets_available = False
            self._reachability_cache[function] = None
            return None

        output = (result.get("output") or "").strip()
        lines = output.splitlines()
        rc_line = lines[-1] if lines else ""
        body_lines = lines[:-1] if rc_line.startswith("__rc=") else lines
        rc = rc_line.split("=", 1)[1] if rc_line.startswith("__rc=") else ""

        if rc not in ("", "0"):
            # Non-zero rc means the wrapper doesn't understand `targets` or
            # /out/$SANITIZER isn't present. Disable further probing.
            self._arvo_targets_available = False
            self._reachability_cache[function] = None
            return None

        self._arvo_targets_available = True
        matches = [line.strip() for line in body_lines if line.strip()]
        self._reachability_cache[function] = matches
        return matches

    @staticmethod
    def _file_slug(file_path: str) -> str:
        return file_path.replace("/", "_").replace(".", "_")

    def _save_incremental(
        self,
        file_path: str,
        file_hypotheses: list[VulnHypothesis],
        aggregate_hypotheses: list[VulnHypothesis],
        *,
        files_done: int,
        files_total: int,
    ) -> None:
        """Persist per-file and running-aggregate progress after each file.

        Writes are idempotent (overwrite) so an interrupted run retains the
        latest snapshot on disk. Exceptions are swallowed so that I/O hiccups
        cannot abort the in-progress scan.
        """
        slug = self._file_slug(file_path)
        try:
            per_file = VulnHypotheses(
                hypotheses=list(file_hypotheses),
                generation_notes=(
                    f"scan_filter results for {file_path}: "
                    f"{len(file_hypotheses)} final hypotheses."
                ),
            )
            self.store.write_handoff("file_hypothesis", per_file, hypothesis_id=slug)
        except Exception as exc:  # noqa: BLE001
            self._log(f"[scan_filter] failed to save per-file handoff for {file_path}: {exc}")

        try:
            partial = VulnHypotheses(
                hypotheses=list(aggregate_hypotheses),
                generation_notes=(
                    f"PARTIAL: {files_done}/{files_total} files processed, "
                    f"{len(aggregate_hypotheses)} hypotheses so far."
                ),
            )
            self.store.write_handoff("hypotheses_partial", partial)
        except Exception as exc:  # noqa: BLE001
            self._log(f"[scan_filter] failed to save partial aggregate: {exc}")

        self.store.append_event(
            "file_hypothesis_completed",
            {
                "file_path": file_path,
                "hypotheses_count": len(file_hypotheses),
                "aggregate_count": len(aggregate_hypotheses),
                "progress": f"{files_done}/{files_total}",
            },
        )

    def _persist_stage3_trace(
        self,
        index: int,
        hypothesis: dict,
        filter_result: dict,
        rel_path: str,
        safe_name: str,
    ) -> None:
        """Write a single sub-agent's trace + verdict to disk.

        Name intentionally still says "stage3" — it writes to the on-disk
        ``stage3_filter/`` path, kept for backward compatibility with existing
        run outputs, decoupled from the ``_run_independent_static_filtering``
        name used for this step elsewhere in the code.

        Called once per hypothesis right after its filter agent returns so that
        a crash or interrupt in a later hypothesis never discards the work of
        completed ones. I/O errors are logged and swallowed.
        """
        summary = hypothesis.get("hypothesis", hypothesis).get("summary", "")
        try:
            self.store.save_trace(
                f"stage3_filter/hyp_{index:02d}_{safe_name}.json",
                {
                    "file": rel_path,
                    "hypothesis_index": index,
                    "summary": summary,
                    "verdict": filter_result.get("verdict", ""),
                    "confidence": filter_result.get("confidence", 0.0),
                    "reason": filter_result.get("reason", ""),
                    "reasoning": filter_result.get("reasoning", ""),
                    "model_cost": filter_result.get("model_cost", 0),
                    "model_calls": filter_result.get("model_calls", 0),
                    "trajectory": filter_result.get("trajectory", []),
                    "error": filter_result.get("error"),
                },
            )
        except Exception as exc:  # noqa: BLE001
            self._log(
                f"[scan_filter] failed to save stage3 trace for hyp {index} "
                f"in {rel_path}: {exc}"
            )
            return

        try:
            self.store.append_event(
                "filter_agent_completed",
                {
                    "file_path": rel_path,
                    "hypothesis_index": index,
                    "verdict": filter_result.get("verdict", ""),
                    "confidence": filter_result.get("confidence", 0.0),
                    "model_cost": filter_result.get("model_cost", 0),
                    "model_calls": filter_result.get("model_calls", 0),
                },
            )
        except Exception as exc:  # noqa: BLE001
            self._log(
                f"[scan_filter] failed to append filter_agent_completed event "
                f"for hyp {index} in {rel_path}: {exc}"
            )

    def _enumerate_files(self, project_path: str) -> list[str]:
        """Enumerate matching source files inside the container.

        Skips fuzzing infrastructure directories (afl, honggfuzz, etc.)
        that live alongside the target project under /src/.
        """
        prune_clauses = " ".join(
            f"-path '{project_path.rstrip('/')}/{d}' -prune -o"
            for d in EXCLUDED_DIRS
        )
        name_clauses = [f"-name '*{ext}'" for ext in self.file_extensions]
        find_expr = " -o ".join(name_clauses)
        cmd = f"find {project_path} {prune_clauses} \\( {find_expr} \\) -type f -print 2>/dev/null | sort"

        result = self.env.execute(cmd)
        output = (result.get("output") or "").strip()
        if not output:
            return []

        prefix = project_path.rstrip("/") + "/"
        relative = []
        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue
            rel = line[len(prefix):] if line.startswith(prefix) else line
            if rel:
                relative.append(rel)
        return relative

    def _read_file_from_container(self, project_path: str, rel_path: str) -> tuple[str, str]:
        """Read a file's contents from the Docker container.

        Returns ``(source, resolved_rel_path)``. If the direct path
        ``{project_path}/{rel_path}`` is not a regular file (e.g. because the
        project sits under a subdirectory like ``/src/openssl/``), fall back
        to searching for any file matching the relative path beneath
        ``project_path`` and use the first hit. On failure both return values
        are empty strings and a warning is logged.

        Previously this method blindly ``cat``ed the composed path and merged
        stderr into stdout, so a missing-file error message ended up being fed
        into the tree-sitter parser and the summarizer as if it were source
        code (producing "0 functions" and harness-only hypotheses).
        """
        project_root = project_path.rstrip("/")
        direct = f"{project_root}/{rel_path}"

        check = self.env.execute(f"test -f '{direct}' && echo OK || echo NO")
        status = (check.get("output") or "").strip().splitlines()
        resolved = direct if status and status[-1] == "OK" else ""

        if not resolved:
            # File isn't at the naive path. Try to locate it under project_root.
            safe_rel = rel_path.replace("'", "'\\''")
            locate_cmd = (
                f"find {project_root} -path '*/{safe_rel}' -type f "
                f"2>/dev/null | head -1"
            )
            found = (self.env.execute(locate_cmd).get("output") or "").strip().splitlines()
            candidate = found[0].strip() if found else ""
            if candidate:
                resolved = candidate
                self._log(
                    f"[scan_filter] target-file {rel_path!r} not at {direct!r}; "
                    f"using discovered path {resolved!r}"
                )

        if not resolved:
            self._log(
                f"[scan_filter] WARNING: could not locate {rel_path!r} under "
                f"{project_root!r}; skipping file"
            )
            return "", ""

        cat = self.env.execute(f"cat '{resolved}'")
        source = cat.get("output") or ""

        # Recompute rel_path relative to project_root so downstream artefacts
        # point at the real location the model/PoC stages will see.
        new_rel = resolved[len(project_root) + 1:] if resolved.startswith(project_root + "/") else rel_path
        return source, new_rel

    def _discover_harness(self, project_path: str) -> tuple[str, str]:
        """Find and read the fuzzer harness (LLVMFuzzerTestOneInput) source.

        Returns (markdown_context, raw_source). Both empty strings if not found.
        """
        # Search for LLVMFuzzerTestOneInput in fuzz-related directories
        cmd = (
            f"grep -rl 'LLVMFuzzerTestOneInput' {project_path} "
            f"--include='*.cpp' --include='*.c' --include='*.cc' 2>/dev/null "
            f"| head -10"
        )
        result = self.env.execute(cmd)
        paths = (result.get("output") or "").strip().splitlines()
        if not paths:
            return "", ""

        # Prefer files in fuzz/fuzzer directories, or the shortest path
        fuzz_paths = [p for p in paths if "fuzz" in p.lower()]
        chosen = fuzz_paths[0] if fuzz_paths else paths[0]

        result = self.env.execute(f"cat '{chosen.strip()}'")
        source = (result.get("output") or "").strip()
        if source:
            prefix = project_path.rstrip("/") + "/"
            rel = chosen.strip()
            if rel.startswith(prefix):
                rel = rel[len(prefix):]
            self._log(f"[scan_filter] Found harness: {rel} ({len(source)} chars)")
            md = f"## Fuzzer Harness (`{rel}`)\n```cpp\n{source}\n```"
            return md, source
        return "", ""

    def _run_proposal_phase_for_file(
        self, rel_path: str, project_path: str, source: str,
        cost_tracker: CostTracker | None = None,
        check_results: list[dict] | None = None,
        harness_context: str = "",
        harness_source: str = "",
    ) -> tuple[list[dict], dict, list[dict], list[dict]]:
        """Run the Initial Hypothesis Proposal band (Figure 3) for one file:
        extract functions, summarize file content, synthesize hypotheses.

        Returns (all_hypotheses, wholefile_result, focused_results, function_analyses).
        """
        file_path = Path(rel_path)

        # Build check analysis context for the summarize phase
        # Pass ALL functions (not just unchecked) so the model knows which params
        # ARE validated and avoids generating hypotheses about already-checked params
        check_context = ""
        if check_results:
            check_context = format_check_analysis_context(check_results, unchecked_only=False)
            if check_context:
                n_unchecked_funcs = sum(1 for r in check_results if r.get("unchecked_params"))
                self._log(f"  [scan_filter] Check analysis: {n_unchecked_funcs} functions with unchecked params")

        # Run constraint analysis (call-site args, bounds, harness params)
        constraint_analysis = run_constraint_analysis(
            source, rel_path,
            harness_source=harness_source,
            check_results=check_results,
        )
        constraint_ctx = format_constraint_context(constraint_analysis)
        if constraint_ctx:
            n_constraints = len(constraint_analysis.get("constraints", {}))
            n_summaries = len(constraint_analysis.get("summaries", {}))
            self._log(
                f"  [scan_filter] Constraint analysis: {n_summaries} functions with call-site info, "
                f"{n_constraints} with bounds constraints"
            )
            check_context = (check_context + "\n\n" + constraint_ctx) if check_context else constraint_ctx

        self._log(f"  [scan_filter] Summarizing {rel_path}...")
        summary, deep_summary, summary_msgs = phase_summarize(
            self.model_name, file_path, source, self.model_kwargs,
            cost_tracker=cost_tracker,
            check_analysis_context=check_context,
            harness_context=harness_context,
        )

        self._log(f"  [scan_filter] Parsing functions in {rel_path}...")
        functions = parse_functions(file_path, source)
        total_found = len(functions)
        if total_found > self.max_functions:
            functions = functions[:self.max_functions]
        self._log(f"  [scan_filter] Found {total_found} functions (using {len(functions)})")

        batches = make_batches(functions)

        # Build focused passes: standard passes + optional unchecked-params pass
        focused_passes = list(FOCUSED_PASSES)
        if check_results:
            unchecked_pass = build_unchecked_params_pass(check_results)
            if unchecked_pass:
                focused_passes.append(unchecked_pass)
                self._log(f"  [scan_filter] Added unchecked-params focused pass")

        total_tasks = 1 + len(focused_passes) + len(batches)
        effective_workers = min(self.max_workers, total_tasks)

        wholefile_result: dict = {}
        focused_results: list[dict] = [{} for _ in focused_passes]
        function_analyses: list[dict] = [{}] * len(batches)
        completed = 0

        with ThreadPoolExecutor(max_workers=effective_workers) as executor:
            futures: dict = {}
            futures[executor.submit(
                phase_analyze_wholefile, self.model_name, file_path, summary_msgs, self.model_kwargs,
                cost_tracker=cost_tracker,
            )] = ("wholefile", None)
            for idx, prompt in enumerate(focused_passes):
                futures[executor.submit(
                    phase_analyze_focused, self.model_name, file_path, summary_msgs, prompt, self.model_kwargs,
                    cost_tracker=cost_tracker,
                )] = ("focused", idx)
            for idx, batch in enumerate(batches):
                futures[executor.submit(
                    phase_analyze_functions, self.model_name, file_path, batch, summary_msgs, self.model_kwargs,
                    cost_tracker=cost_tracker,
                    check_results=check_results,
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
                    self._log(f"  [scan_filter] [{completed}/{total_tasks}] {kind} done for {rel_path}")
                except Exception as e:
                    self._log(f"  [scan_filter] [{completed}/{total_tasks}] ERROR ({kind}): {e}")

        all_hypotheses = aggregate_hypotheses(wholefile_result, focused_results, function_analyses)
        return all_hypotheses, wholefile_result, focused_results, function_analyses

    def _run_sanitizer_aware_triage(
        self, all_hypotheses: list[dict], source: str,
        cost_tracker: CostTracker | None = None,
    ) -> tuple[list[dict], list[dict]]:
        """In-scope Hypotheses via sanitizer-aware triage (Figure 3, refinement
        band) — one LLM call per hypothesis judging is_vulnerability/sanitizers.

        Returns (in_scope_hypotheses, classify_trace).
        """
        source_lines = source.splitlines()
        dedup_kwargs = dict(self.model_kwargs)
        dedup_kwargs["temperature"] = 0.0

        self._log(f"  [scan_filter] Classifying {len(all_hypotheses)} hypotheses...")

        classifications: dict[int, dict] = {}
        with ThreadPoolExecutor(max_workers=self.max_workers) as pool:
            futures = {
                pool.submit(classify_hypothesis, h, self.model_name, dedup_kwargs, source_lines,
                            cost_tracker=cost_tracker): i
                for i, h in enumerate(all_hypotheses)
            }
            done = 0
            for future in as_completed(futures):
                idx = futures[future]
                done += 1
                try:
                    classifications[idx] = future.result()
                    c = classifications[idx]
                    is_vuln = c["is_vulnerability"]
                    sans = c.get("sanitizers", [])
                    if is_vuln and sans:
                        tag = "+".join(s.upper() for s in sans)
                    elif is_vuln:
                        tag = "VUL(no-san)"
                    else:
                        tag = "NOT"
                    self._log(
                        f"  [scan_filter] [{done}/{len(all_hypotheses)}] "
                        f"{tag} — {c['reason'][:70]}"
                    )
                except Exception as e:
                    classifications[idx] = {
                        "is_vulnerability": False, "sanitizers": [], "is_asan": False,
                        "cwe_ids": [], "reason": f"error: {e}",
                        "raw_response": "", "prompt": "",
                    }

        # Build classify trace
        classify_trace = []
        for i, h in enumerate(all_hypotheses):
            c = classifications[i]
            classify_trace.append({
                "index": i,
                "summary": h.get("hypothesis", h).get("summary", ""),
                "is_vulnerability": c["is_vulnerability"],
                "sanitizers": c.get("sanitizers", []),
                "is_asan": c.get("is_asan", False),  # back-compat
                "attacker_controls": c.get("attacker_controls", "none"),
                "primitive": c.get("primitive", "none"),
                "severity": c.get("severity", "none"),
                "cwe_ids": c["cwe_ids"],
                "reason": c["reason"],
                "raw_response": c.get("raw_response", ""),
                "prompt": c.get("prompt", ""),
            })

        # Filter: keep vulnerabilities triggerable by ANY supported sanitizer
        # (ASAN/UBSAN/MSAN — matches what tools/validate.py actually tests
        # and what crash_signals.py recognizes).
        valid_indices = [
            i for i in range(len(all_hypotheses))
            if classifications[i]["is_vulnerability"]
            and bool(classifications[i].get("sanitizers"))
        ]
        self._log(
            f"  [scan_filter] Filtered: "
            f"{len(all_hypotheses) - len(valid_indices)} not sanitizer-triggerable, "
            f"{len(valid_indices)} remain"
        )

        for i, h in enumerate(all_hypotheses):
            c = classifications[i]
            h["_cwe_ids"] = c["cwe_ids"]
            h["_is_vulnerability"] = c["is_vulnerability"]
            h["_sanitizers"] = c.get("sanitizers", [])
            h["_is_asan"] = c.get("is_asan", False)  # back-compat
            h["_attacker_controls"] = c.get("attacker_controls", "none")
            h["_primitive"] = c.get("primitive", "none")
            h["_severity"] = c.get("severity", "none")
            if not c["is_vulnerability"]:
                h["_removed"] = f"Not a vulnerability: {c['reason']}"
            elif not c.get("sanitizers"):
                h["_removed"] = f"Not sanitizer-triggerable: {c['reason']}"

        in_scope_hypotheses = [all_hypotheses[i] for i in valid_indices]
        return in_scope_hypotheses, classify_trace

    def _run_root_cause_dedup(
        self, in_scope_hypotheses: list[dict],
        cost_tracker: CostTracker | None = None,
    ) -> tuple[list[dict], dict]:
        """Merged Hypotheses via deduplicate root causes (Figure 3, refinement
        band): deterministic line/CWE-overlap prefilter + pairwise LLM judgement
        + union-find merge (see ``dedup_hypotheses``).

        Returns (merged_hypotheses, dedup_trace).
        """
        dedup_kwargs = dict(self.model_kwargs)
        dedup_kwargs["temperature"] = 0.0
        cwe_map = {j: h.get("_cwe_ids", []) for j, h in enumerate(in_scope_hypotheses)}

        merged, removed, comparisons = dedup_hypotheses(
            in_scope_hypotheses, cwe_map, self.model_name, dedup_kwargs,
            workers=self.max_workers, cost_tracker=cost_tracker,
        )
        self._log(f"  [scan_filter] Dedup: {len(in_scope_hypotheses)} -> {len(merged)} (removed {len(removed)})")

        dedup_trace = {
            "candidate_pairs": len(comparisons),
            "comparisons": comparisons,
            "kept_count": len(merged),
            "removed": [
                {"summary": r.get("hypothesis", r).get("summary", ""), "reason": r.get("_removed", "")}
                for r in removed
            ],
        }

        return merged, dedup_trace

    def _annotate_reachability(self, kept: list[dict], rel_path: str) -> None:
        """Advisory reachability signal feeding Figure 3's "Reachability-Annotated
        Hypotheses" box — but note this only *annotates* via ``arvo targets``
        (deterministic, no LLM call); the actual filtering that box's name implies
        happens separately, in ``_run_independent_static_filtering``.

        Annotate ``kept`` hypotheses in-place with reachability metadata. Sets on
        each hypothesis dict:
            * ``_reachable`` — ``True`` if at least one fuzz-target binary
              links the hotspot function, ``False`` if none, ``None`` if the
              lookup is unavailable (non-multi-sanitizer image, stripped
              binaries, missing ``arvo targets`` command).
            * ``_fuzz_targets`` — list of binary names that link the function.

        Reachability is a *ranking signal only*; it does not remove any
        hypothesis from ``kept``.
        """
        reach_counts = {"true": 0, "false": 0, "unknown": 0}
        for h in kept:
            inner = h.get("hypothesis", h)
            hotspots = inner.get("hotspots", [])
            func = hotspots[0].get("function") if hotspots else None
            matches = self._lookup_fuzz_targets(func)
            if matches is None:
                h["_reachable"] = None
                h["_fuzz_targets"] = []
                reach_counts["unknown"] += 1
            else:
                h["_reachable"] = len(matches) > 0
                h["_fuzz_targets"] = matches
                reach_counts["true" if matches else "false"] += 1
        self._log(
            f"  [scan_filter] Reachability ({rel_path}): "
            f"{reach_counts['true']} reachable, {reach_counts['false']} "
            f"unreachable, {reach_counts['unknown']} unknown"
        )

    def _run_independent_static_filtering(
        self, kept: list[dict], target_file: str,
        cost_tracker: CostTracker | None = None,
        check_results: list[dict] | None = None,
        safe_name: str | None = None,
    ) -> tuple[list[dict], dict[int, dict]]:
        """Independent static filtering (Figure 3, refinement band) via a Docker
        sub-agent: a real coding agent (``DefaultAgent`` + unrestricted ``bash``
        tool) run in a tool-use loop against the same shared container the whole
        scan runs in — NOT a single LLM call, and NOT restricted to
        ``target_file``; its prompt explicitly encourages tracing callers/callees
        repo-wide. See ``run_filter_agent`` for the prompt/agent setup.

        Returns (final_hypotheses, filter_results).

        When ``safe_name`` is provided, each sub-agent's trace is persisted to
        ``stage3_filter/hyp_<i>_<safe_name>.json`` (name kept for backward
        compatibility with existing run outputs) immediately after the agent
        returns, so a crash or interrupt mid-stage never loses the work of
        already-completed sub-agents.
        """
        self._log(f"  [scan_filter] Independent static filtering: {len(kept)} hypotheses with sub-agents...")

        filter_results: dict[int, dict] = {}
        # Run filter agents sequentially in the shared container to avoid interference
        # (DefaultAgent may modify shell state)
        for i, h in enumerate(kept):
            try:
                filter_results[i] = run_filter_agent(
                    h, self.env, target_file,
                    self.filter_model, self.filter_model_config,
                    self.agent_step_limit, self.agent_cost_limit,
                    check_results=check_results,
                    log_fn=self.step_log_fn,
                    log_prefix=f"  [scan_filter] [{i+1}/{len(kept)}] ",
                )
                v = filter_results[i]
                if cost_tracker is not None:
                    cost_tracker.add(v.get("model_cost", 0), v.get("model_calls", 0))
                self._log(
                    f"  [scan_filter] [{i+1}/{len(kept)}] {v['verdict']} "
                    f"(conf={v['confidence']:.2f}, ${v.get('model_cost', 0):.3f}) — "
                    f"{v['reason'][:60]}"
                )
            except Exception as e:
                filter_results[i] = {
                    "verdict": "VALID", "confidence": 0.0, "reason": str(e),
                    "reasoning": "", "error": str(e),
                }

            # Persist this sub-agent's trace immediately so partial progress
            # survives an interrupt or later crash in the same stage.
            if safe_name:
                self._persist_stage3_trace(i, h, filter_results[i], target_file, safe_name)

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
            else:
                final_hypotheses.append(h)

        self._log(
            f"  [scan_filter] Sub-agent filter: {len(kept)} -> {len(final_hypotheses)} "
            f"(removed {len(kept) - len(final_hypotheses)})"
        )
        return final_hypotheses, filter_results

    def _rank_for_confirmation(self, all_vuln_hypotheses: list[VulnHypothesis]) -> None:
        """Ranked Hypothesis Queue via rank for PoC confirmation (Figure 3,
        refinement band) — deterministic, no LLM call. Sorts in-place by
        (reachable, severity, confidence) — descending — so that
        reachable-from-fuzzer, higher-severity, higher-confidence hypotheses
        land at the top of hypotheses.json and survive ``--top-n``, then
        reassigns sequential hypothesis IDs to match the new order.
        """
        all_vuln_hypotheses.sort(key=hypothesis_priority_key, reverse=True)
        for idx, h in enumerate(all_vuln_hypotheses, start=1):
            h.hypothesis_id = f"SF{idx:02d}"
        self._log(f"[scan_filter] Ranked {len(all_vuln_hypotheses)} hypotheses for PoC confirmation")

    def run(
        self,
        project_path: str,
        arvo_mode: bool = False,
        target_file: str | None = None,
    ) -> VulnHypotheses:
        """Run the scan-and-filter pipeline.

        Args:
            project_path: Absolute path to the project inside the container.
            arvo_mode: Whether this is an ARVO target.
            target_file: If given, scan only this file (relative to project_path).
                         Otherwise scan all matching files.

        Returns:
            VulnHypotheses with filtered, converted hypotheses.
        """
        self.store.append_event("scan_filter_start", {
            "project_path": project_path,
            "arvo_mode": arvo_mode,
            "target_file": target_file,
            "max_workers": self.max_workers,
            "file_extensions": self.file_extensions,
        })

        cost_tracker = CostTracker()

        # Discover fuzzer harness for reachability context
        harness_context = ""
        harness_source = ""
        if arvo_mode:
            harness_context, harness_source = self._discover_harness(project_path)

        # Determine files to scan
        if target_file:
            files = [target_file]
        else:
            files = self._enumerate_files(project_path)
        self._log(f"[scan_filter] Found {len(files)} file(s) to scan")

        if not files:
            self._log("[scan_filter] No matching source files found")
            return VulnHypotheses(hypotheses=[], generation_notes="No matching source files found.")

        all_vuln_hypotheses: list[VulnHypothesis] = []
        files_completed = 0

        for rel_path in files:
            self._log(f"\n[scan_filter] === Processing {rel_path} ===")
            files_completed += 1

            # Read source from container. The resolver may rewrite rel_path
            # (e.g. 'ssl/ssl_rsa.c' -> 'openssl/ssl/ssl_rsa.c') when the
            # project lives under a subdirectory of project_path.
            source, resolved_rel = self._read_file_from_container(project_path, rel_path)
            if not source.strip():
                self._log(f"[scan_filter] Skipping empty/unreadable file: {rel_path}")
                continue
            if resolved_rel and resolved_rel != rel_path:
                rel_path = resolved_rel

            # Sanitize filename for trace filenames
            safe_name = rel_path.replace("/", "__").replace(".", "_")

            # Run static check analysis on the source
            self._log(f"[scan_filter] Running static check analysis on {rel_path}...")
            check_results = run_check_analysis(source, rel_path)
            n_funcs_analyzed = len(check_results)
            n_with_unchecked = sum(1 for r in check_results if r.get("unchecked_params"))
            self._log(
                f"[scan_filter] Check analysis: {n_funcs_analyzed} functions, "
                f"{n_with_unchecked} with unchecked params"
            )

            # Initial Hypothesis Proposal (Figure 3, proposal band)
            self._log(f"[scan_filter] Initial Hypothesis Proposal for {rel_path}")
            cost_before = cost_tracker.snapshot()
            all_hypotheses, wf, fr, fa = self._run_proposal_phase_for_file(
                rel_path, project_path, source, cost_tracker=cost_tracker,
                check_results=check_results,
                harness_context=harness_context,
                harness_source=harness_source,
            )
            s1_cost, s1_calls = cost_tracker.snapshot()
            s1_cost -= cost_before[0]
            s1_calls -= cost_before[1]
            self._log(
                f"[scan_filter] Initial Hypothesis Proposal done: {len(all_hypotheses)} raw hypotheses "
                f"(${s1_cost:.4f}, {s1_calls} calls)"
            )

            # Save Initial Hypothesis Proposal trace (on-disk name kept as
            # "stage1_*" for backward compatibility with existing run outputs).
            self.store.save_trace(f"stage1_{safe_name}.json", {
                "file": rel_path,
                "wholefile": {
                    "analysis": wf.get("analysis", ""),
                    "hypotheses": wf.get("hypotheses", []),
                    "messages": wf.get("messages", []),
                },
                "focused": [
                    {
                        "focus_prompt": fr_item.get("focus_prompt", ""),
                        "analysis": fr_item.get("analysis", ""),
                        "hypotheses": fr_item.get("hypotheses", []),
                        "messages": fr_item.get("messages", []),
                    }
                    for fr_item in fr
                ],
                "functions": [
                    {
                        "function": fa_item.get("function", ""),
                        "functions": fa_item.get("functions", []),
                        "formulation": fa_item.get("formulation", ""),
                        "hypotheses": fa_item.get("hypotheses", []),
                        "messages": fa_item.get("messages_formulation", []),
                    }
                    for fa_item in fa
                ],
                "aggregated_hypotheses": all_hypotheses,
                "num_raw_hypotheses": len(all_hypotheses),
                "check_analysis": {
                    "functions_analyzed": n_funcs_analyzed,
                    "functions_with_unchecked": n_with_unchecked,
                    "details": check_results[:20],  # save first 20 for trace
                },
                "cost": s1_cost,
                "calls": s1_calls,
            })

            if not all_hypotheses:
                continue

            # all_hypotheses is this file's contribution to the Raw Hypothesis
            # Pool (Figure 3 proposal-band output) — refinement band starts here.
            # Triage + dedup cost/calls are tracked as one combined span (as
            # before) so the on-disk stage2_classify_*.json trace content is
            # unchanged.
            self._log(f"[scan_filter] Sanitizer-aware triage for {rel_path}")
            cost_before = cost_tracker.snapshot()
            in_scope, classify_trace = self._run_sanitizer_aware_triage(
                all_hypotheses, source, cost_tracker=cost_tracker,
            )
            self._log(f"[scan_filter] Deduplicate root causes for {rel_path}")
            merged, dedup_trace = self._run_root_cause_dedup(
                in_scope, cost_tracker=cost_tracker,
            )
            s2_cost, s2_calls = cost_tracker.snapshot()
            s2_cost -= cost_before[0]
            s2_calls -= cost_before[1]
            self._log(
                f"[scan_filter] Triage + dedup done: {len(merged)} merged "
                f"(${s2_cost:.4f}, {s2_calls} calls)"
            )

            # Save triage/dedup traces (on-disk names kept as "stage2_*" for
            # backward compatibility with existing run outputs).
            self.store.save_trace(f"stage2_classify_{safe_name}.json", {
                "file": rel_path,
                "input_count": len(all_hypotheses),
                "classifications": classify_trace,
                "cost": s2_cost,
                "calls": s2_calls,
            })
            self.store.save_trace(f"stage2_dedup_{safe_name}.json", {
                "file": rel_path,
                **dedup_trace,
            })

            kept = merged
            if not kept:
                self._log(f"[scan_filter] No hypotheses survived classification/dedup for {rel_path}")
                continue

            # Reachability annotation feeding the "Reachability-Annotated
            # Hypotheses" box (Figure 3): use ``arvo targets <symbol>`` to
            # discover which fuzz-target binaries link each hypothesis's
            # hotspot function. Result is advisory (a ranking signal), NOT a
            # hard filter — unreachable-from-fuzzer bugs are still worth
            # reporting, they just drop in priority.
            if arvo_mode:
                self._annotate_reachability(kept, rel_path)

            # Independent static filtering (Figure 3, refinement band) via a
            # Docker sub-agent. Traces are persisted per-hypothesis inside
            # _run_independent_static_filtering as each sub-agent returns, so
            # partial progress survives an interrupt.
            self._log(f"[scan_filter] Independent static filtering for {rel_path}")
            cost_before = cost_tracker.snapshot()
            final, filter_results = self._run_independent_static_filtering(
                kept, rel_path, cost_tracker=cost_tracker, check_results=check_results,
                safe_name=safe_name,
            )
            s3_cost, s3_calls = cost_tracker.snapshot()
            s3_cost -= cost_before[0]
            s3_calls -= cost_before[1]
            self._log(
                f"[scan_filter] Independent static filtering done: {len(final)} final "
                f"(${s3_cost:.4f}, {s3_calls} calls)"
            )

            # Convert to VulnHypothesis
            file_vuln_hypotheses: list[VulnHypothesis] = []
            for i, hyp in enumerate(final):
                vh = _convert_hypothesis(hyp, len(all_vuln_hypotheses) + 1, rel_path)
                all_vuln_hypotheses.append(vh)
                file_vuln_hypotheses.append(vh)

            # Real-time persistence: save per-file hypotheses and the
            # running aggregate after every file so that an interrupted
            # run retains completed progress on disk.
            self._save_incremental(
                rel_path,
                file_vuln_hypotheses,
                all_vuln_hypotheses,
                files_done=files_completed,
                files_total=len(files),
            )

        self._rank_for_confirmation(all_vuln_hypotheses)

        total_cost, total_calls = cost_tracker.snapshot()
        self._log(
            f"[scan_filter] Pipeline complete: {len(all_vuln_hypotheses)} hypotheses "
            f"from {len(files)} file(s) — total cost: ${total_cost:.4f}, {total_calls} LLM calls"
        )

        self.store.append_event("scan_filter_end", {
            "total_hypotheses": len(all_vuln_hypotheses),
            "files_scanned": len(files),
            "total_cost": total_cost,
            "total_calls": total_calls,
        })

        generation_notes = (
            f"Scan-filter pipeline: scanned {len(files)} file(s), "
            f"produced {len(all_vuln_hypotheses)} filtered hypotheses. "
            f"Cost: ${total_cost:.4f} ({total_calls} LLM calls)."
        )
        return VulnHypotheses(hypotheses=all_vuln_hypotheses, generation_notes=generation_notes)
