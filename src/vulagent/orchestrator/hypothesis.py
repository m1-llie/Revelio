"""Hypothesis orchestrator: parallel file-level vulnerability scanning."""

from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any

from vulagent.artifacts.schema import VulnHypotheses, VulnHypothesis
from vulagent.artifacts.store import ArtifactStore
from vulagent.models import get_api_keys_pool
from vulagent.orchestrator.file_hypothesis import FileHypothesisRunner
from vulagent.orchestrator.parsers import parse_hypotheses
from vulagent.orchestrator.types import AgentRunResult

DEFAULT_FILE_EXTENSIONS = [".c", ".cpp", ".cc", ".cxx"]

EXCLUDED_DIRS = {
    "afl", "aflplusplus", "honggfuzz", "libfuzzer", "fuzzer-test-suite",
    "DictFuzzer", "centipede", "fuzztest",
}


class HypothesisOrchestrator:
    """Orchestrate parallel file-level hypothesis generation.

    Enumerates source files in the container, runs a FileHypothesisRunner per file in parallel using ThreadPoolExecutor, then merges and re-ranks all hypotheses by confidence.
    """

    def __init__(
        self,
        *,
        env: Any,
        model_name: str,
        model_config: dict[str, Any] | None = None,
        store: ArtifactStore,
        log_fn: Any | None = None,
        api_keys: list[str] | None = None,
        file_extensions: list[str] | None = None,
        max_workers: int = 4,
    ):
        self.env = env
        self.model_name = model_name
        self.model_config = model_config or {}
        self.store = store
        self.log_fn = log_fn
        self.file_extensions = file_extensions or DEFAULT_FILE_EXTENSIONS
        self.max_workers = max_workers
        self.api_keys = api_keys or get_api_keys_pool()
        self._key_counter = 0
        self._key_lock = threading.Lock()

    def _log(self, message: str) -> None:
        if self.log_fn:
            self.log_fn(message)

    def _get_next_api_key(self) -> str | None:
        """Assign an API key via round-robin from the pool."""
        if not self.api_keys:
            return None
        with self._key_lock:
            key = self.api_keys[self._key_counter % len(self.api_keys)]
            self._key_counter += 1
            return key

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

    def _run_single_file(
        self,
        file_path: str,
        project_path: str,
        arvo_mode: bool,
        config_path: Path | None,
    ) -> tuple[str, AgentRunResult | None, VulnHypotheses | None]:
        """Run hypothesis generation for a single file."""
        api_key = self._get_next_api_key()
        runner = FileHypothesisRunner(
            env=self.env,
            model_name=self.model_name,
            model_config=self.model_config,
            store=self.store,
            log_fn=self.log_fn,
            api_key=api_key,
        )

        run_result = runner.run(
            file_path=file_path,
            project_path=project_path,
            arvo_mode=arvo_mode,
            config_path=config_path,
        )

        if run_result.exit_status != "Submitted":
            self._log(f"FileHypothesisRunner[{file_path}]: non-submitted status {run_result.exit_status}")
            return file_path, run_result, None

        try:
            hypotheses = parse_hypotheses(run_result.result)
        except ValueError as e:
            self._log(
                f"FileHypothesisRunner[{file_path}]: failed to parse hypotheses: {e}\n"
                f"Raw result (first 500 chars): {run_result.result[:500]}"
            )
            return file_path, run_result, None
        return file_path, run_result, hypotheses

    def run(
        self,
        project_path: str,
        arvo_mode: bool = False,
        config_path: Path | None = None,
    ) -> VulnHypotheses:
        """Run parallel file-level hypothesis generation and merge results.

        Args:
            project_path: Absolute path to the project inside the container.
            arvo_mode: Whether this is an ARVO target.
            config_path: Optional override for file_hypothesis.yaml.

        Returns:
            VulnHypotheses with merged, re-numbered, confidence-sorted hypotheses.
        """
        self.store.append_event("hypothesis_orchestrator_start", {
            "project_path": project_path,
            "arvo_mode": arvo_mode,
            "max_workers": self.max_workers,
            "file_extensions": self.file_extensions,
        })

        files = self._enumerate_files(project_path)
        self._log(f"HypothesisOrchestrator: found {len(files)} source files to scan")
        self.store.append_event("files_enumerated", {"count": len(files), "files": files[:50]})

        if not files:
            self._log("HypothesisOrchestrator: no matching source files found")
            return VulnHypotheses(hypotheses=[], generation_notes="No matching source files found.")

        all_hypotheses: list[VulnHypothesis] = []
        all_trajectories: dict[str, Any] = {}
        total_cost = 0.0
        total_calls = 0

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {
                executor.submit(self._run_single_file, f, project_path, arvo_mode, config_path): f
                for f in files
            }

            for future in as_completed(futures):
                file_path = futures[future]
                fp, run_result, hypotheses = future.result()

                if run_result:
                    key = f"file_hypothesis_{fp.replace('/', '_')}"
                    all_trajectories[key] = run_result.trajectory
                    total_cost += run_result.model_cost
                    total_calls += run_result.model_calls

                if hypotheses and hypotheses.hypotheses:
                    all_hypotheses.extend(hypotheses.hypotheses)

        # Sort by confidence descending and re-number IDs globally
        all_hypotheses.sort(key=lambda h: h.confidence, reverse=True)
        for idx, h in enumerate(all_hypotheses, start=1):
            h.hypothesis_id = f"H{idx:02d}"

        self._log(
            f"HypothesisOrchestrator: merged {len(all_hypotheses)} hypotheses "
            f"from {len(files)} files (cost=${total_cost:.4f}, calls={total_calls})"
        )

        self.store.write_aggregated_trajectory({"agents": all_trajectories})
        self.store.append_event("hypothesis_orchestrator_end", {
            "total_hypotheses": len(all_hypotheses),
            "total_cost": total_cost,
            "total_calls": total_calls,
        })

        generation_notes = (
            f"Scanned {len(files)} files with {self.max_workers} parallel workers. "
            f"Total cost: ${total_cost:.4f}, API calls: {total_calls}."
        )
        return VulnHypotheses(hypotheses=all_hypotheses, generation_notes=generation_notes)
