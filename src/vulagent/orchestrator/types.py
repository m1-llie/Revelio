"""Types for the multi-agent orchestrator."""

from __future__ import annotations

from dataclasses import dataclass
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
    report_path: Path | None = None
    poc_path: Path | None = None
    script_path: Path | None = None
    validation_path: Path | None = None


Parser = Callable[[str], Any]
