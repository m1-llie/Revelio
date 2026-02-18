"""Default agent specs for the multi-agent workflow."""

from __future__ import annotations

from pathlib import Path

from vulagent.orchestrator.types import AgentSpec


def default_agent_specs(config_dir: Path) -> dict[str, AgentSpec]:
    """Return the default AgentSpec set for the multi-agent pipeline."""
    return {
        # Combined stage: does its own repository review and directly outputs hypotheses.
        # This removes cross-agent handover between reviewer -> hypotheses.
        "hypothesis": AgentSpec(
            name="HypothesisAgent",
            config_path=config_dir / "hypothesis.yaml",
            task="Review the codebase and produce a ranked list of vulnerability hypotheses.",
        ),
        "poc_builder": AgentSpec(
            name="PoCBuilderAgent",
            config_path=config_dir / "poc_builder.yaml",
            task="Build a deterministic PoC generator for the assigned hypothesis.",
            max_attempts=2,
        ),
        "validator": AgentSpec(
            name="ValidatorAgent",
            config_path=config_dir / "validator.yaml",
            task="Validate the PoC by running the reproduction command and capturing crash evidence.",
        ),
        "reporter": AgentSpec(
            name="ReporterAgent",
            config_path=config_dir / "reporter.yaml",
            task="Write a concise bug report from the confirmed crash evidence.",
        ),
    }
