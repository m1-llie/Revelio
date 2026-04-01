"""Multi-agent orchestrator for vulnerability detection."""

from __future__ import annotations

from dataclasses import asdict
from pathlib import Path
from typing import Any

import yaml

from vulagent import __version__
from vulagent.agents.default import DefaultAgent
from vulagent.artifacts.schema import (
    ArtifactMeta,
    BugReport,
    PoCRecipe,
    ValidationResult,
    VulnHypotheses,
)
from vulagent.artifacts.store import ArtifactStore
from vulagent.models import get_model
from vulagent.orchestrator.context import ContextPacketBuilder, render_context_packet
from vulagent.orchestrator.hypothesis import HypothesisOrchestrator
from vulagent.orchestrator.parsers import (
    _load_structured,
    parse_bug_report,
    parse_hypotheses,
    parse_poc_recipe,
    parse_validation_result,
)
from vulagent.tools.validate import make_validate_tool
from vulagent.orchestrator.types import AgentRunResult, AgentSpec, OrchestratorResult


def _class_path(obj: Any) -> str:
    return f"{obj.__class__.__module__}.{obj.__class__.__name__}"


def _discover_fuzz_targets(env: Any, function: str | None) -> list[str]:
    """Find fuzz targets whose binary contains the given function symbol.

    Uses ``arvo targets <symbol>`` (nm-based lookup).  Returns an empty
    list when the arvo script doesn't support the ``targets`` subcommand
    (e.g. original ARVO images) or when no targets match.
    """
    if not function:
        return []
    result = env.execute(f"arvo targets {function} 2>/dev/null || true")
    output = (result.get("output") or "").strip()
    if not output:
        return []
    return [line.strip() for line in output.splitlines() if line.strip()]


def _asdict(obj: Any) -> dict[str, Any]:
    if hasattr(obj, "__dataclass_fields__"):
        return asdict(obj)  # type: ignore[arg-type]
    return obj


def _load_yaml(path: Path) -> dict[str, Any]:
    return yaml.safe_load(path.read_text()) or {}


class AgentRunner:
    def __init__(
        self,
        *,
        model_name: str,
        env: Any,
        store: ArtifactStore,
        log_fn: Any | None = None,
        checkpoint_every: int = 5,
        global_model_config: dict[str, Any] | None = None,
    ):
        self.model_name = model_name
        self.env = env
        self.store = store
        self.log_fn = log_fn
        self.checkpoint_every = checkpoint_every
        self.global_model_config = global_model_config or {}

    def run(
        self,
        spec: AgentSpec,
        *,
        extra_vars: dict[str, Any],
        tools: list | None = None,
    ) -> AgentRunResult:
        config_data = _load_yaml(spec.config_path)
        agent_config = config_data.get("agent", {})
        model_config = config_data.get("model", {})
        # Merge global model config (e.g. api_key/base_url from CLI) into per-agent config
        if self.global_model_config:
            for key, val in self.global_model_config.items():
                if isinstance(val, dict) and isinstance(model_config.get(key), dict):
                    model_config[key] = {**model_config[key], **val}
                else:
                    model_config.setdefault(key, val)
        effective_model_name = spec.model_name or self.model_name
        if spec.api_key:
            model_config.setdefault("model_kwargs", {})["api_key"] = spec.api_key
        model = get_model(effective_model_name, model_config)

        agent = DefaultAgent(model, self.env, tools=tools, **agent_config)

        step_counter = {"n": 0}
        real_step = agent.step

        def step_with_progress():
            step_counter["n"] += 1
            if self.log_fn:
                self.log_fn(f"{spec.name}: step {step_counter['n']} running...")
            result = real_step()
            if self.checkpoint_every > 0 and step_counter["n"] % self.checkpoint_every == 0:
                self._checkpoint(spec.name, agent, step_counter["n"])
            return result

        agent.step = step_with_progress

        self.store.append_event("agent_start", {"agent": spec.name})
        if self.log_fn:
            self.log_fn(f"{spec.name}: started")
        exit_status, result = agent.run(spec.task, **extra_vars)
        self.store.append_event("agent_end", {"agent": spec.name, "exit_status": exit_status})
        if self.log_fn:
            self.log_fn(
                f"{spec.name}: finished with {exit_status} "
                f"(steps={step_counter['n']}, calls={agent.model.n_calls}, cost=${agent.model.cost:.4f})"
            )

        trajectory = {
            "info": {
                "exit_status": exit_status,
                "submission": result,
                "model_stats": {
                    "instance_cost": agent.model.cost,
                    "api_calls": agent.model.n_calls,
                },
                "mini_version": __version__,
                "agent_name": spec.name,
                "config": {
                    "agent": _asdict(agent.config),
                    "model": _asdict(agent.model.config),
                    "environment": _asdict(agent.env.config),
                    "agent_type": _class_path(agent),
                    "model_type": _class_path(agent.model),
                    "environment_type": _class_path(agent.env),
                },
            },
            "messages": agent.messages,
            "trajectory_format": "vul-agent-1",
        }

        return AgentRunResult(
            agent_name=spec.name,
            exit_status=exit_status,
            result=result,
            trajectory=trajectory,
            model_cost=agent.model.cost,
            model_calls=agent.model.n_calls,
        )

    def _checkpoint(self, agent_name: str, agent: DefaultAgent, steps: int) -> None:
        trajectory = {
            "info": {
                "exit_status": "IN_PROGRESS",
                "submission": "",
                "model_stats": {
                    "instance_cost": agent.model.cost,
                    "api_calls": agent.model.n_calls,
                },
                "mini_version": __version__,
                "agent_name": agent_name,
            },
            "messages": agent.messages,
            "trajectory_format": "vul-agent-1",
            "checkpoint_step": steps,
        }
        self.store.write_aggregated_trajectory({"agents": {agent_name: trajectory}})


def verify_crash(validation: ValidationResult) -> bool:
    """Programmatic cross-check of crash evidence, independent of LLM self-report."""
    from vulagent.tools.validate import check_crash

    return check_crash(
        " ".join([validation.output_excerpt or "", " ".join(validation.indicators)]),
        validation.returncode,
    )


class MultiAgentOrchestrator:
    def __init__(
        self,
        *,
        store: ArtifactStore,
        env: Any,
        model_name: str,
        project_path: str,
        arvo_mode: bool,
        top_n: int = 10,
        max_poc_attempts: int = 2,
        log_fn: Any | None = None,
        on_success: Any | None = None,
        pipeline_mode: str = "detect",
        max_workers: int = 4,
        api_keys: list[str] | None = None,
        file_extensions: list[str] | None = None,
        hypotheses_override: VulnHypotheses | None = None,
        model_config: dict[str, Any] | None = None,
    ):
        self.store = store
        self.env = env
        self.model_name = model_name
        self.project_path = project_path
        self.arvo_mode = arvo_mode
        self.top_n = int(top_n)
        self.max_poc_attempts = max_poc_attempts
        self._aggregate_trajectories: dict[str, Any] = {"agents": {}}
        self._context_builder = ContextPacketBuilder()
        self._artifacts: dict[str, Any] = {}
        self._log_fn = log_fn
        self._on_success = on_success
        self.pipeline_mode = pipeline_mode
        self.max_workers = max_workers
        self.api_keys = api_keys
        self.file_extensions = file_extensions
        self.hypotheses_override = hypotheses_override
        self.model_config = model_config or {}

    def _log(self, message: str) -> None:
        if self._log_fn:
            self._log_fn(message)

    def _report_path(self, hypothesis_id: str) -> str:
        return f"{self.project_path}/final_report_{hypothesis_id}.md"

    def _report_exists(self, hypothesis_id: str) -> bool:
        try:
            report_path = self._report_path(hypothesis_id)
            result = self.env.execute(f"test -f {report_path} && echo OK || echo MISSING")
            return "OK" in (result.get("output") or "")
        except Exception:
            return False

    def _record_trajectory(
        self,
        run_result: AgentRunResult,
        *,
        hypothesis_id: str | None = None,
        attempt: int | None = None,
    ) -> None:
        parts = [run_result.agent_name]
        if hypothesis_id:
            parts.append(hypothesis_id)
        if attempt is not None:
            parts.append(f"attempt{attempt}")
        key = "_".join(parts)
        self._aggregate_trajectories["agents"][key] = run_result.trajectory
        self.store.write_aggregated_trajectory(self._aggregate_trajectories)

    @staticmethod
    def _is_rejected(result_text: str) -> bool:
        """Check if the PoC agent rejected the hypothesis as invalid."""
        try:
            import yaml
            parsed = yaml.safe_load(result_text)
            if isinstance(parsed, dict):
                # Check status field
                if str(parsed.get("status", "")).lower() == "rejected":
                    return True
                # Check payload.rejected
                payload = parsed.get("payload", {})
                if isinstance(payload, dict) and payload.get("rejected"):
                    return True
        except Exception:
            pass
        # Fallback: check for "rejected": true in raw text
        return '"rejected": true' in result_text or '"rejected":true' in result_text

    @staticmethod
    def _extract_reject_reason(result_text: str) -> str:
        """Extract the rejection reason from agent output."""
        try:
            import yaml
            parsed = yaml.safe_load(result_text)
            if isinstance(parsed, dict):
                payload = parsed.get("payload", {})
                if isinstance(payload, dict) and payload.get("reason"):
                    return str(payload["reason"])
                if parsed.get("analysis"):
                    return str(parsed["analysis"])[:200]
        except Exception:
            pass
        return "hypothesis rejected by PoC agent"

    def _check_run_status(self, run_result: AgentRunResult, stage: str) -> OrchestratorResult | None:
        if run_result.exit_status != "Submitted":
            self.store.append_event(
                "agent_failure",
                {"agent": run_result.agent_name, "stage": stage, "exit_status": run_result.exit_status},
            )
            return OrchestratorResult(
                status="failure",
                summary=f"{run_result.agent_name} failed with {run_result.exit_status}.",
                run_dir=self.store.run_dir,
            )
        return None

    def run(
        self,
        *,
        poc_builder: AgentSpec,
        reporter: AgentSpec,
    ) -> OrchestratorResult:
        runner = AgentRunner(
            model_name=self.model_name,
            env=self.env,
            store=self.store,
            log_fn=self._log_fn,
            global_model_config=self.model_config,
        )
        validate_tool = make_validate_tool(self.env)

        self.store.append_event("run_start", {"arvo_mode": self.arvo_mode, "pipeline_mode": self.pipeline_mode})
        common_vars = {"project_path": self.project_path, "arvo_mode": self.arvo_mode, "top_n": self.top_n}

        # Stage 1: Hypothesis generation (skip if override provided)
        if self.hypotheses_override is not None:
            self._log("Using pre-generated hypotheses (override)...")
            hypotheses = self.hypotheses_override
        else:
            self._log("Running HypothesisOrchestrator (parallel file scanning)...")
            hypothesis_orch = HypothesisOrchestrator(
                env=self.env,
                model_name=self.model_name,
                store=self.store,
                log_fn=self._log_fn,
                api_keys=self.api_keys,
                file_extensions=self.file_extensions,
                max_workers=self.max_workers,
            )
            hypotheses = hypothesis_orch.run(
                project_path=self.project_path,
                arvo_mode=self.arvo_mode,
            )

        if not hypotheses.hypotheses:
            self.store.append_event("no_hypotheses", {})
            return OrchestratorResult(
                status="failure",
                summary="No hypotheses were generated from file scanning.",
                run_dir=self.store.run_dir,
            )

        # Truncate to top_n
        hypotheses.hypotheses = hypotheses.hypotheses[:self.top_n]
        self._artifacts["hypotheses"] = hypotheses
        self.store.write_handoff("hypotheses", hypotheses)
        self._log(f"HypothesisOrchestrator produced {len(hypotheses.hypotheses)} hypotheses (top {self.top_n})")

        # If pipeline_mode is "project", stop after hypothesis generation
        if self.pipeline_mode == "project":
            self.store.append_event("run_complete_project_mode", {
                "hypotheses_count": len(hypotheses.hypotheses),
            })
            return OrchestratorResult(
                status="success",
                summary=f"Generated {len(hypotheses.hypotheses)} hypotheses (project mode).",
                run_dir=self.store.run_dir,
            )

        # Stages 2-3: PoC building + validation (per hypothesis)
        report_files: list[str] = []
        poc_files: list[str] = []
        script_files: list[str] = []
        success_count = 0

        for item in hypotheses.hypotheses:
            hypothesis_dict = item.to_dict()
            self._log(f"Running PoCBuilder for {item.hypothesis_id} ({item.title})...")
            self.store.append_event("poc_start", {"hypothesis_id": item.hypothesis_id})

            # Discover which fuzz targets can reach the hypothesis function.
            # For multi-target images we iterate targets; for single-target
            # (ARVO) or non-arvo mode, matched_targets is empty and we fall
            # through to a single run with no DEFAULT_FUZZER override.
            matched_targets = (
                _discover_fuzz_targets(self.env, item.function)
                if self.arvo_mode else []
            )

            if matched_targets:
                self._log(
                    f"  {item.hypothesis_id}: function '{item.function}' found in "
                    f"{len(matched_targets)} target(s): {', '.join(matched_targets)}"
                )
                self.store.append_event("targets_matched", {
                    "hypothesis_id": item.hypothesis_id,
                    "function": item.function,
                    "targets": matched_targets,
                })

            # Try each matched target (or a single run with no override).
            # Stop on first crash.
            target_attempts = matched_targets or [None]
            crash_detected = False
            poc_recipe = None
            poc_section: dict = {}

            for fuzz_target in target_attempts:
                if fuzz_target:
                    self.env.execute(f"export DEFAULT_FUZZER={fuzz_target}")
                    self._log(f"  Trying target: {fuzz_target}")

                poc_context = self._context_builder.build(
                    poc_builder.name,
                    run_manifest={"project_path": self.project_path, "arvo_mode": self.arvo_mode},
                    hypothesis=hypothesis_dict,
                )
                extra_vars = {
                    **common_vars,
                    "hypothesis_id": item.hypothesis_id,
                    "hypothesis_title": item.title,
                    "hypothesis_description": item.description,
                    "context_packet": render_context_packet(poc_context),
                    "max_validate_attempts": self.max_poc_attempts,
                    "fuzz_target": fuzz_target or "",
                }

                poc_run = runner.run(
                    poc_builder, extra_vars=extra_vars, tools=[validate_tool],
                )
                self._record_trajectory(poc_run, hypothesis_id=item.hypothesis_id)

                if self._check_run_status(poc_run, "poc_builder"):
                    self._log(f"  PoCBuilder failed for target {fuzz_target or 'default'}")
                    continue

                poc_recipe = parse_poc_recipe(poc_run.result)
                self._artifacts["poc"] = poc_recipe
                self.store.write_handoff("poc_recipe", poc_recipe, hypothesis_id=item.hypothesis_id)
                if poc_recipe.input_path:
                    poc_files.append(poc_recipe.input_path)
                if poc_recipe.script_path:
                    script_files.append(poc_recipe.script_path)

                poc_data = _load_structured(poc_run.result)
                payload = poc_data.get("payload", {})
                if isinstance(payload, str):
                    payload = _load_structured(payload)
                poc_section = payload.get("poc", payload)
                if not isinstance(poc_section, dict):
                    poc_section = {}
                crash_detected = bool(poc_section.get("crash_detected", False))

                if crash_detected:
                    break  # found a crash, no need to try more targets

            if not crash_detected:
                self.store.append_event(
                    "hypothesis_exhausted",
                    {"hypothesis_id": item.hypothesis_id, "stage": "poc_builder", "reason": "no_crash_detected"},
                )
                self._log(f"No crash detected for {item.hypothesis_id}, moving to next hypothesis.")
                continue

            # Stage 3: Report generation
            self._log(f"Crash confirmed for {item.hypothesis_id}. Generating report...")
            validation = ValidationResult(
                hypothesis_id=item.hypothesis_id,
                crash_detected=True,
                returncode=poc_section.get("returncode"),
                output_excerpt=poc_section.get("output_excerpt", ""),
                indicators=list(poc_section.get("indicators") or []),
                reproduction_command=poc_section.get("reproduction_command"),
            )
            self._artifacts["validation"] = validation
            self.store.write_handoff("validation", validation, hypothesis_id=item.hypothesis_id)

            reporter_hint = ""
            report = None
            for r_attempt in range(1, 3):
                reporter_context = self._context_builder.build(
                    reporter.name,
                    run_manifest={"project_path": self.project_path, "arvo_mode": self.arvo_mode},
                    hypothesis=hypothesis_dict,
                    poc=poc_recipe,
                    validation=validation,
                )
                reporter_run = runner.run(
                    reporter,
                    extra_vars={
                        **extra_vars,
                        "context_packet": render_context_packet(reporter_context),
                        "reporter_hint": reporter_hint,
                    },
                )
                self._record_trajectory(reporter_run, hypothesis_id=item.hypothesis_id, attempt=r_attempt)
                if failure := self._check_run_status(reporter_run, "reporter"):
                    self.store.append_event(
                        "reporter_failed",
                        {"hypothesis_id": item.hypothesis_id, "reason": failure.summary},
                    )
                    break
                report = parse_bug_report(reporter_run.result)
                self.store.save_report_meta(
                    report,
                    hypothesis_id=item.hypothesis_id,
                    meta=ArtifactMeta(
                        artifact_type="BugReport",
                        agent_name=reporter.name,
                        hypothesis_id=item.hypothesis_id,
                    ),
                )
                self.store.write_handoff("report", report, hypothesis_id=item.hypothesis_id)
                if report and report.report_path:
                    report_files.append(report.report_path)
                if self._report_exists(item.hypothesis_id):
                    break
                self.store.append_event(
                    "report_missing",
                    {"hypothesis_id": item.hypothesis_id, "attempt": r_attempt},
                )
                reporter_hint = (
                    f"WARNING: The previous run did not create /src/final_report_{item.hypothesis_id}.md. "
                    "You MUST write the report file before calling finish. "
                    f"Verify it exists with `test -f /src/final_report_{item.hypothesis_id}.md`."
                )

            if not self._report_exists(item.hypothesis_id):
                self.store.append_event(
                    "hypothesis_exhausted",
                    {"hypothesis_id": item.hypothesis_id, "stage": "reporter", "reason": "report_file_missing"},
                )
                self._log(f"Hypothesis {item.hypothesis_id}: report file not written")
                continue

            self.store.append_event("run_success", {"hypothesis_id": item.hypothesis_id})
            self._log(f"Hypothesis {item.hypothesis_id} confirmed and reported.")
            if self._on_success:
                self._on_success(
                    hypothesis_id=item.hypothesis_id,
                    report_path=(report.report_path if report else ""),
                    poc_path=(poc_recipe.input_path if poc_recipe else ""),
                    script_path=(poc_recipe.script_path if poc_recipe else ""),
                )
            success_count += 1

        report_files = list(dict.fromkeys(report_files))
        poc_files = list(dict.fromkeys(poc_files))
        script_files = list(dict.fromkeys(script_files))

        if success_count > 0:
            self.store.append_event("run_success_all", {"count": success_count})
            self._log(f"Run finished: {success_count} hypothesis confirmed.")
            return OrchestratorResult(
                status="success",
                summary=f"Confirmed {success_count} vulnerabilities.",
                run_dir=self.store.run_dir,
                report_paths=report_files,
                poc_paths=poc_files,
                script_paths=script_files,
            )

        self.store.append_event("run_failure", {})
        return OrchestratorResult(
            status="failure",
            summary="No hypothesis yielded a confirmed crash.",
            run_dir=self.store.run_dir,
            report_paths=report_files,
            poc_paths=poc_files,
            script_paths=script_files,
            validation_paths=validation_files,
        )
