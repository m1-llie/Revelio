"""Types for the multi-agent orchestrator."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable


@dataclass
class AgentSpec:
    name: str
    config_path: Path
    task: str
    max_attempts: int = 1
    role: str | None = None


@dataclass
class AgentRunResult:
    agent_name: str
    exit_status: str
    result: str
    trajectory: dict[str, Any]
    model_cost: float
    model_calls: int
    raw_output: dict[str, Any] | None = None


@dataclass
class OrchestratorResult:
    status: str
    summary: str
    run_dir: Path
    report_paths: list[str] = field(default_factory=list)
    poc_paths: list[str] = field(default_factory=list)
    script_paths: list[str] = field(default_factory=list)
    validation_paths: list[str] = field(default_factory=list)


Parser = Callable[[str], Any]
