#!/usr/bin/env python3
from __future__ import annotations

import os
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console

from vulagent.config import get_config_path
from vulagent.agents import VulAgent
from vulagent.environments.docker import DockerEnvironment
from vulagent.models import get_model
from vulagent.run.utils import save_traj
from ..utils.docker import copy_from_container

console = Console()
app = typer.Typer(rich_markup_mode="rich", pretty_exceptions_show_locals=False)

DEFAULT_CONFIG = "fuzz_construct.yaml"
DEFAULT_DOCKER_IMAGE = "n132/arvo:24993-vul"
WORKSPACE_ROOT = Path("/workspace")
PROJECT_ROOT = WORKSPACE_ROOT / "project"
DEFAULT_OUTPUT = None


@app.command()
def main(
    project_path: Path = typer.Option(
        Path("examples/bof"),
        "--project-path",
        "-p",
        help="Path to the C/C++ project to analyse.",
    ),
    output_dir: Path | None = typer.Option(
        None,
        "--output-dir",
        help="Output directory",
    ),
    config: str = typer.Option(
        DEFAULT_CONFIG,
        "--config",
        "-c",
        help="Agent config file (YAML) relative to config directory.",
    ),
    model: Optional[str] = typer.Option(
        None,
        "--model",
        envvar="MODEL_NAME",
        help="Model name (set via --model or MODEL_NAME env var).",
    ),
    docker_image: str = typer.Option(
        DEFAULT_DOCKER_IMAGE,
        "--docker-image",
        help="Docker image to use for the sandbox environment.",
    ),
    keep_container: bool = typer.Option(
        False,
        "--keep-container",
        help="Do not auto-remove container on exit (useful for debugging).",
    ),
    run_id: Optional[str] = typer.Option(
        None,
        "--run-id",
        help="Name for logging/trajectory/solution",
    ),
) -> None:
    """Analyze *project_path* for memory-safety issues inside Docker."""

    assert output_dir is not None, "You must specify an output directory for safety reason"

    project_path = project_path.resolve()

    config_path = get_config_path(config)
    config_data = load_yaml(config_path)

    console.print(f"[bold green]Using config:[/bold green] {config_path}")

    model_name = model or os.getenv("MODEL_NAME")
    if not model_name:
        console.print("[bold red]No model specified.[/bold red] Set MODEL_NAME or use --model.")
        raise typer.Exit(1)

    console.print(f"[bold green]Model:[/bold green] {model_name}")
    console.print(f"[bold green]Docker image:[/bold green] {docker_image}")
    console.print(f"[bold green]Project path:[/bold green] {project_path}\n")

    LOG_DIR = Path(f"{output_dir}/log")
    TRAJ_DIR = Path(f"{output_dir}/trajectory")
    REPORT_DIR = Path(f"{output_dir}/report")
    POC_DIR = Path(f"{output_dir}/poc")

    # Prepare timestamped output paths
    # Use UTC to keep timestamps consistent across hosts
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    TRAJ_DIR.mkdir(parents=True, exist_ok=True)
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    POC_DIR.mkdir(parents=True, exist_ok=True)

    run_id = run_id or f"{project_path.name}_{timestamp}"

    output_path = TRAJ_DIR / f"{run_id}_traj.json"
    log_path = LOG_DIR / f"{run_id}_log.json"
    report_path = REPORT_DIR / f"{run_id}_report.md"
    poc_path = POC_DIR / f"{run_id}_poc"
    assert all([not p.exists() for p in [output_path, log_path, report_path, poc_path]]), f"Previous run exists: {run_id}"

    workspace_project = PROJECT_ROOT / project_path.name
    run_args = ["--rm"] if not keep_container else []
    docker_env = DockerEnvironment(image=docker_image, run_args=run_args)

    try:
        env_config = config_data.get("environment", {})
        docker_env.config.env.update(env_config.get("env", {}))

        agent_config = config_data.get("agent", {})
        model_config = config_data.get("model", {})

        agent = VulAgent(
            log_path=log_path,
            console=console,
            model=get_model(model_name, model_config),
            env=docker_env,
            **agent_config,
        )

        task_description = (
            "Analyze the project and find the command to fuzz the project using AFL++ for an hour"
        )

        console.print("[bold green]Starting agent...[/bold green]")
        console.print(f"[cyan]Outputs will be written to:[/cyan] {output_dir}")
        console.print(f"[cyan]Current run ID:[/cyan] {run_id}\n")
        started_at = datetime.now(timezone.utc)
        exit_status, result = agent.run(
            task_description,
            project_path=str(workspace_project),
        )
        finished_at = datetime.now(timezone.utc)
        report_source = WORKSPACE_ROOT / "final_report.md"
        poc_source = WORKSPACE_ROOT / "poc"
        copied_report: Path | None = copy_from_container(docker_env, report_source, report_path, console)
        copied_poc: Path | None = copy_from_container(docker_env, poc_source, poc_path, console)

        info = {
            "exit_status": exit_status,
            "project_path": str(project_path),
            "docker_image": docker_image,
            "started_at_utc": started_at.isoformat(),
            "finished_at_utc": finished_at.isoformat(),
            "duration_seconds": (finished_at - started_at).total_seconds(),
        }
        info["report_available"] = copied_report is not None
        info["poc_available"] = copied_poc is not None
        info["verification"] = None

        save_traj(agent, output_path, exit_status=exit_status, result=result, extra_info=info)
        console.print(f"\n[bold green]Trajectory saved to:[/bold green] {output_path}")

    finally:
        if not keep_container:
            docker_env.cleanup()


def load_yaml(path: Path) -> dict:
    import yaml

    return yaml.safe_load(path.read_text()) or {}


def extract_reproduction_command(result: str) -> Optional[str]:
    marker = "reproduction_command:"
    for line in result.splitlines():
        if line.strip().startswith(marker):
            command = line.split(marker, 1)[1].strip()
            return None if command.lower() == "none" else command
    return None


if __name__ == "__main__":
    app()
