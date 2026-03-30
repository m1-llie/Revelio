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

from vulagent.artifacts.schema import CodeReference, VulnHypotheses, VulnHypothesis
from vulagent.artifacts.store import ArtifactStore
from vulagent.orchestrator.scan_filter_stages import (
    FOCUSED_PASSES,
    CostTracker,
    FunctionInfo,
    aggregate_hypotheses,
    build_unchecked_params_pass,
    classify_hypothesis,
    dedup_hypotheses,
    format_check_analysis_context,
    make_batches,
    parse_functions,
    phase_analyze_focused,
    phase_analyze_functions,
    phase_analyze_wholefile,
    phase_summarize,
    run_check_analysis,
    run_filter_agent,
)

logger = logging.getLogger("scan_filter")

DEFAULT_FILE_EXTENSIONS = [".c", ".cpp", ".cc", ".cxx", ".h", ".hpp"]


def _convert_hypothesis(hyp: dict, index: int, file_path: str) -> VulnHypothesis:
    """Convert a scan_and_filter dict hypothesis to a VulnHypothesis dataclass."""
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
    return VulnHypothesis(
        hypothesis_id=f"SF{index:02d}",
        title=h.get("summary", "Unknown vulnerability"),
        description=h.get("summary", ""),
        file_path=file_path,
        function=func,
        trigger=None,
        preconditions=[],
        expected_crash="; ".join(str(w) for w in warnings) if warnings else None,
        confidence=hyp.get("_filter_confidence", 0.5),
        references=references,
    )


class ScanFilterOrchestrator:
    """Orchestrate the scan-and-filter pipeline inside a Docker container.

    Stages:
    1. Multi-pass hypothesis generation (summarize + whole-file + focused + per-function)
    2. LLM classification & dedup (is_vulnerability, is_asan, CWE, then LLM dedup)
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
        self.file_extensions = file_extensions or DEFAULT_FILE_EXTENSIONS
        self.max_workers = max_workers
        self.filter_model = filter_model or model_name
        # Build filter model config for get_model() (used by DefaultAgent in Stage 3)
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

    def _log(self, message: str) -> None:
        if self.log_fn:
            self.log_fn(message)

    def _enumerate_files(self, project_path: str) -> list[str]:
        """Enumerate matching source files inside the container."""
        name_clauses = [f"-name '*{ext}'" for ext in self.file_extensions]
        find_expr = " -o ".join(name_clauses)
        cmd = f"find {project_path} \\( {find_expr} \\) -type f 2>/dev/null | sort"

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

    def _read_file_from_container(self, project_path: str, rel_path: str) -> str:
        """Read a file's contents from the Docker container."""
        full_path = f"{project_path.rstrip('/')}/{rel_path}"
        result = self.env.execute(f"cat '{full_path}'")
        return result.get("output") or ""

    def _run_stage1_for_file(
        self, rel_path: str, project_path: str, source: str,
        cost_tracker: CostTracker | None = None,
        check_results: list[dict] | None = None,
    ) -> tuple[list[dict], dict, list[dict], list[dict]]:
        """Run Stage 1 (multi-pass hypothesis generation) for a single file.

        Returns (all_hypotheses, wholefile_result, focused_results, function_analyses).
        """
        file_path = Path(rel_path)

        # Build check analysis context for the summarize phase
        check_context = ""
        if check_results:
            check_context = format_check_analysis_context(check_results, unchecked_only=True)
            if check_context:
                n_unchecked_funcs = sum(1 for r in check_results if r.get("unchecked_params"))
                self._log(f"  [scan_filter] Check analysis: {n_unchecked_funcs} functions with unchecked params")

        self._log(f"  [scan_filter] Summarizing {rel_path}...")
        summary, deep_summary, summary_msgs = phase_summarize(
            self.model_name, file_path, source, self.model_kwargs,
            cost_tracker=cost_tracker,
            check_analysis_context=check_context,
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

    def _run_stage2(
        self, all_hypotheses: list[dict], source: str,
        cost_tracker: CostTracker | None = None,
    ) -> tuple[list[dict], list[dict], dict]:
        """Run Stage 2 (classification & dedup).

        Returns (kept, classify_trace, dedup_trace).
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
                    is_vuln = classifications[idx]["is_vulnerability"]
                    is_asan = classifications[idx]["is_asan"]
                    self._log(
                        f"  [scan_filter] [{done}/{len(all_hypotheses)}] "
                        f"{('ASAN' if is_asan else 'VUL') if is_vuln else 'NOT'} — "
                        f"{classifications[idx]['reason'][:70]}"
                    )
                except Exception as e:
                    classifications[idx] = {
                        "is_vulnerability": False, "is_asan": False, "cwe_ids": [], "reason": f"error: {e}",
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
                "is_asan": c["is_asan"],
                "cwe_ids": c["cwe_ids"],
                "reason": c["reason"],
                "raw_response": c.get("raw_response", ""),
                "prompt": c.get("prompt", ""),
            })

        # Filter: keep only ASAN-triggerable vulnerabilities
        valid_indices = [
            i for i in range(len(all_hypotheses))
            if classifications[i]["is_vulnerability"] and classifications[i]["is_asan"]
        ]
        self._log(
            f"  [scan_filter] Filtered: {len(all_hypotheses) - len(valid_indices)} non-asan, "
            f"{len(valid_indices)} remain"
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

        kept, removed, comparisons = dedup_hypotheses(valid_hyps, cwe_map, self.model_name, dedup_kwargs,
                                                      workers=self.max_workers, cost_tracker=cost_tracker)
        self._log(f"  [scan_filter] Dedup: {len(valid_hyps)} -> {len(kept)} (removed {len(removed)})")

        dedup_trace = {
            "candidate_pairs": len(comparisons),
            "comparisons": comparisons,
            "kept_count": len(kept),
            "removed": [
                {"summary": r.get("hypothesis", r).get("summary", ""), "reason": r.get("_removed", "")}
                for r in removed
            ],
        }

        return kept, classify_trace, dedup_trace

    def _run_stage3(
        self, kept: list[dict], target_file: str,
        cost_tracker: CostTracker | None = None,
        check_results: list[dict] | None = None,
    ) -> tuple[list[dict], dict[int, dict]]:
        """Run Stage 3 (Docker sub-agent filtering). Returns (final_hypotheses, filter_results)."""
        self._log(f"  [scan_filter] Stage 3: filtering {len(kept)} hypotheses with sub-agents...")

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
                )
                v = filter_results[i]
                # Accumulate filter agent cost
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

        for rel_path in files:
            self._log(f"\n[scan_filter] === Processing {rel_path} ===")

            # Read source from container
            source = self._read_file_from_container(project_path, rel_path)
            if not source.strip():
                self._log(f"[scan_filter] Skipping empty file: {rel_path}")
                continue

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

            # Stage 1: Hypothesis generation
            self._log(f"[scan_filter] Stage 1: Hypothesis generation for {rel_path}")
            cost_before = cost_tracker.snapshot()
            all_hypotheses, wf, fr, fa = self._run_stage1_for_file(
                rel_path, project_path, source, cost_tracker=cost_tracker,
                check_results=check_results,
            )
            s1_cost, s1_calls = cost_tracker.snapshot()
            s1_cost -= cost_before[0]
            s1_calls -= cost_before[1]
            self._log(
                f"[scan_filter] Stage 1 done: {len(all_hypotheses)} raw hypotheses "
                f"(${s1_cost:.4f}, {s1_calls} calls)"
            )

            # Save Stage 1 trace
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

            # Stage 2: Classification & dedup
            self._log(f"[scan_filter] Stage 2: Classification & dedup for {rel_path}")
            cost_before = cost_tracker.snapshot()
            kept, classify_trace, dedup_trace = self._run_stage2(
                all_hypotheses, source, cost_tracker=cost_tracker,
            )
            s2_cost, s2_calls = cost_tracker.snapshot()
            s2_cost -= cost_before[0]
            s2_calls -= cost_before[1]
            self._log(
                f"[scan_filter] Stage 2 done: {len(kept)} kept "
                f"(${s2_cost:.4f}, {s2_calls} calls)"
            )

            # Save Stage 2 traces
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

            if not kept:
                self._log(f"[scan_filter] No hypotheses survived classification/dedup for {rel_path}")
                continue

            # Stage 3: Docker sub-agent filtering
            self._log(f"[scan_filter] Stage 3: Sub-agent filtering for {rel_path}")
            cost_before = cost_tracker.snapshot()
            final, filter_results = self._run_stage3(
                kept, rel_path, cost_tracker=cost_tracker, check_results=check_results,
            )
            s3_cost, s3_calls = cost_tracker.snapshot()
            s3_cost -= cost_before[0]
            s3_calls -= cost_before[1]
            self._log(
                f"[scan_filter] Stage 3 done: {len(final)} final "
                f"(${s3_cost:.4f}, {s3_calls} calls)"
            )

            # Save Stage 3 traces (one file per hypothesis)
            for i, h in enumerate(kept):
                fr_item = filter_results.get(i, {})
                self.store.save_trace(f"stage3_filter/hyp_{i:02d}_{safe_name}.json", {
                    "file": rel_path,
                    "hypothesis_index": i,
                    "summary": h.get("hypothesis", h).get("summary", ""),
                    "verdict": fr_item.get("verdict", ""),
                    "confidence": fr_item.get("confidence", 0.0),
                    "reason": fr_item.get("reason", ""),
                    "reasoning": fr_item.get("reasoning", ""),
                    "model_cost": fr_item.get("model_cost", 0),
                    "model_calls": fr_item.get("model_calls", 0),
                    "trajectory": fr_item.get("trajectory", []),
                    "error": fr_item.get("error"),
                })

            # Convert to VulnHypothesis
            for i, hyp in enumerate(final):
                vh = _convert_hypothesis(hyp, len(all_vuln_hypotheses) + 1, rel_path)
                all_vuln_hypotheses.append(vh)

        # Sort by confidence descending and re-number
        all_vuln_hypotheses.sort(key=lambda h: h.confidence, reverse=True)
        for idx, h in enumerate(all_vuln_hypotheses, start=1):
            h.hypothesis_id = f"SF{idx:02d}"

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
