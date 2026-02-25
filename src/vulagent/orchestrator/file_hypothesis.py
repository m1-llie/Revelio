"""File-level hypothesis runner for parallel vulnerability scanning."""

from __future__ import annotations

from dataclasses import asdict
from pathlib import Path
from typing import Any

import yaml

from vulagent import __version__
from vulagent.agents.default import DefaultAgent
from vulagent.artifacts.store import ArtifactStore
from vulagent.config import get_config_path
from vulagent.models import get_model
from vulagent.orchestrator.types import AgentRunResult

DEFAULT_CONFIG = "agents/file_hypothesis.yaml"


def _load_yaml(path: Path) -> dict[str, Any]:
    return yaml.safe_load(path.read_text()) or {}


def _class_path(obj: Any) -> str:
    return f"{obj.__class__.__module__}.{obj.__class__.__name__}"


class FileHypothesisRunner:
    """Run a file-level hypothesis agent for a single source file.

    This is the core unit of work in the parallel file-scanning architecture.
    It creates a DefaultAgent loaded from file_hypothesis.yaml, runs it against a single file, and returns the AgentRunResult.
    """

    def __init__(
        self,
        *,
        env: Any,
        model_name: str,
        model_config: dict[str, Any] | None = None,
        store: ArtifactStore,
        log_fn: Any | None = None,
        api_key: str | None = None,
    ):
        self.env = env
        self.model_name = model_name
        self.model_config = model_config or {}
        self.store = store
        self.log_fn = log_fn
        self.api_key = api_key

    def _log(self, message: str) -> None:
        if self.log_fn:
            self.log_fn(message)

    def run(
        self,
        file_path: str,
        project_path: str,
        arvo_mode: bool = False,
        config_path: Path | None = None,
    ) -> AgentRunResult:
        """Run the file hypothesis agent on a single file.

        Args:
            file_path: Relative path to the file within the project.
            project_path: Absolute path to the project root inside the container.
            arvo_mode: Whether this is an ARVO target.
            config_path: Path to YAML config; defaults to agents/file_hypothesis.yaml.

        Returns:
            AgentRunResult with raw result and trajectory.
        """
        resolved_config = config_path or get_config_path(DEFAULT_CONFIG)
        config_data = _load_yaml(resolved_config)

        agent_config = config_data.get("agent", {})
        model_config = {**self.model_config, **config_data.get("model", {})}

        if self.api_key:
            model_config.setdefault("model_kwargs", {})["api_key"] = self.api_key

        model = get_model(self.model_name, model_config)
        agent = DefaultAgent(model, self.env, **agent_config)

        agent_name = f"FileHypothesisAgent[{file_path}]"
        task = f"Analyze the file '{file_path}' for security vulnerabilities."

        step_counter = {"n": 0}
        real_step = agent.step

        def step_with_progress():
            step_counter["n"] += 1
            self._log(f"{agent_name}: step {step_counter['n']}...")
            return real_step()

        agent.step = step_with_progress

        self.store.append_event("agent_start", {"agent": agent_name, "file_path": file_path})
        self._log(f"{agent_name}: started")

        exit_status, result = agent.run(
            task,
            project_path=project_path,
            file_path=file_path,
            arvo_mode=arvo_mode,
            context_packet="",
        )

        self.store.append_event("agent_end", {
            "agent": agent_name,
            "file_path": file_path,
            "exit_status": exit_status,
        })
        self._log(
            f"{agent_name}: finished with {exit_status} "
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
                "agent_name": agent_name,
                "file_path": file_path,
            },
            "messages": agent.messages,
            "trajectory_format": "vul-agent-1",
        }

        return AgentRunResult(
            agent_name=agent_name,
            exit_status=exit_status,
            result=result,
            trajectory=trajectory,
            model_cost=agent.model.cost,
            model_calls=agent.model.n_calls,
        )
