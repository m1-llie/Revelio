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
    CodeReviewNotes,
    PoCRecipe,
    ValidationResult,
    VulnHypotheses,
)
from vulagent.artifacts.store import ArtifactStore
from vulagent.models import get_model
from vulagent.orchestrator.context import ContextPacketBuilder, render_context_packet
from vulagent.orchestrator.parsers import (
    parse_bug_report,
    parse_code_review,
    parse_hypotheses,
    parse_poc_recipe,
    parse_validation_result,
)
from vulagent.orchestrator.types import AgentRunResult, AgentSpec, OrchestratorResult


def _class_path(obj: Any) -> str:
    return f"{obj.__class__.__module__}.{obj.__class__.__name__}"


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
        model_config: dict[str, Any] | None,
        env: Any,
        store: ArtifactStore,
    ):
        self.model_name = model_name
        self.model_config = model_config or {}
        self.env = env
        self.store = store

    def run(self, spec: AgentSpec, *, extra_vars: dict[str, Any]) -> AgentRunResult:
        config_data = _load_yaml(spec.config_path)
        agent_config = config_data.get("agent", {})
        model_config = config_data.get("model", {})
        model = get_model(self.model_name, model_config)

        agent = DefaultAgent(model, self.env, **agent_config)

        self.store.append_log_line("starting agent run", agent=spec.name, event="agent_start")
        exit_status, result = agent.run(spec.task, **extra_vars)
        self.store.append_log_line(
            f"agent finished with {exit_status}", agent=spec.name, event="agent_end"
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

        self.store.append_trajectory(spec.name, trajectory)

        return AgentRunResult(
            agent_name=spec.name,
            exit_status=exit_status,
            result=result,
            trajectory=trajectory,
            model_cost=agent.model.cost,
            model_calls=agent.model.n_calls,
        )


class MultiAgentOrchestrator:
    def __init__(
        self,
        *,
        store: ArtifactStore,
        env: Any,
        model_name: str,
        model_config: dict[str, Any] | None = None,
        project_path: str,
        arvo_mode: bool,
        max_poc_attempts: int = 2,
    ):
        self.store = store
        self.env = env
        self.model_name = model_name
        self.model_config = model_config or {}
        self.project_path = project_path
        self.arvo_mode = arvo_mode
        self.max_poc_attempts = max_poc_attempts
        self._aggregate_trajectories: dict[str, Any] = {"agents": {}}
        self._context_builder = ContextPacketBuilder()
        self._artifacts: dict[str, Any] = {}

    def _record_trajectory(self, run_result: AgentRunResult) -> None:
        self._aggregate_trajectories["agents"][run_result.agent_name] = run_result.trajectory
        self.store.write_aggregated_trajectory(self._aggregate_trajectories)

    def run(
        self,
        *,
        reviewer: AgentSpec,
        hypothesis: AgentSpec,
        poc_builder: AgentSpec,
        validator: AgentSpec,
        reporter: AgentSpec,
    ) -> OrchestratorResult:
        runner = AgentRunner(
            model_name=self.model_name,
            model_config=self.model_config,
            env=self.env,
            store=self.store,
        )

        self.store.append_event("run_start", {"arvo_mode": self.arvo_mode})
        common_vars = {"project_path": self.project_path, "arvo_mode": self.arvo_mode}

        reviewer_context = self._context_builder.build(
            reviewer.name, run_manifest={"project_path": self.project_path, "arvo_mode": self.arvo_mode}
        )
        review_run = runner.run(
            reviewer,
            extra_vars={**common_vars, "context_packet": render_context_packet(reviewer_context)},
        )
        self._record_trajectory(review_run)
        code_review = parse_code_review(review_run.result)
        self._artifacts["code_review"] = code_review
        self.store.append_json_artifact(
            "code_review",
            code_review,
            meta=ArtifactMeta(artifact_type="CodeReviewNotes", agent_name=reviewer.name),
        )

        hypothesis_context = self._context_builder.build(
            hypothesis.name,
            run_manifest={"project_path": self.project_path, "arvo_mode": self.arvo_mode},
            code_review=code_review,
        )
        hypothesis_run = runner.run(
            hypothesis,
            extra_vars={**common_vars, "context_packet": render_context_packet(hypothesis_context)},
        )
        self._record_trajectory(hypothesis_run)
        hypotheses = parse_hypotheses(hypothesis_run.result)
        self._artifacts["hypotheses"] = hypotheses
        self.store.append_json_artifact(
            "hypotheses",
            hypotheses,
            meta=ArtifactMeta(artifact_type="VulnHypotheses", agent_name=hypothesis.name),
        )

        for item in hypotheses.hypotheses:
            for attempt in range(1, self.max_poc_attempts + 1):
                self.store.append_event(
                    "poc_attempt",
                    {"hypothesis_id": item.hypothesis_id, "attempt": attempt},
                )
                hypothesis_dict = item.to_dict()
                poc_context = self._context_builder.build(
                    poc_builder.name,
                    run_manifest={"project_path": self.project_path, "arvo_mode": self.arvo_mode},
                    code_review=code_review,
                    hypothesis=hypothesis_dict,
                )
                extra_vars = {
                    **common_vars,
                    "hypothesis_id": item.hypothesis_id,
                    "hypothesis_title": item.title,
                    "hypothesis_description": item.description,
                    "context_packet": render_context_packet(poc_context),
                }

                poc_run = runner.run(poc_builder, extra_vars=extra_vars)
                self._record_trajectory(poc_run)
                poc_recipe = parse_poc_recipe(poc_run.result)
                self._artifacts["poc"] = poc_recipe
                self.store.append_json_artifact(
                    "poc",
                    poc_recipe,
                    meta=ArtifactMeta(
                        artifact_type="PoCRecipe",
                        agent_name=poc_builder.name,
                        hypothesis_id=item.hypothesis_id,
                    ),
                )

                validation_context = self._context_builder.build(
                    validator.name,
                    run_manifest={"project_path": self.project_path, "arvo_mode": self.arvo_mode},
                    hypothesis=hypothesis_dict,
                    poc=poc_recipe,
                )
                validation_run = runner.run(
                    validator,
                    extra_vars={**extra_vars, "context_packet": render_context_packet(validation_context)},
                )
                self._record_trajectory(validation_run)
                validation = parse_validation_result(validation_run.result)
                self._artifacts["validation"] = validation
                validation_path = self.store.append_json_artifact(
                    "validation",
                    validation,
                    meta=ArtifactMeta(
                        artifact_type="ValidationResult",
                        agent_name=validator.name,
                        hypothesis_id=item.hypothesis_id,
                    ),
                )

                if validation.crash_detected:
                    reporter_context = self._context_builder.build(
                        reporter.name,
                        run_manifest={"project_path": self.project_path, "arvo_mode": self.arvo_mode},
                        code_review=code_review,
                        hypothesis=hypothesis_dict,
                        poc=poc_recipe,
                        validation=validation,
                    )
                    reporter_run = runner.run(
                        reporter,
                        extra_vars={**extra_vars, "context_packet": render_context_packet(reporter_context)},
                    )
                    self._record_trajectory(reporter_run)
                    report = parse_bug_report(reporter_run.result)
                    report_path = self.store.append_json_artifact(
                        "reports",
                        report,
                        meta=ArtifactMeta(
                            artifact_type="BugReport",
                            agent_name=reporter.name,
                            hypothesis_id=item.hypothesis_id,
                        ),
                    )
                    self.store.append_event(
                        "run_success", {"hypothesis_id": item.hypothesis_id}
                    )
                    return OrchestratorResult(
                        status="success",
                        summary="Vulnerability confirmed.",
                        run_dir=self.store.run_dir,
                        report_path=report_path,
                        validation_path=validation_path,
                    )

        self.store.append_event("run_failure", {})
        return OrchestratorResult(
            status="failure",
            summary="No hypothesis yielded a confirmed crash.",
            run_dir=self.store.run_dir,
        )
