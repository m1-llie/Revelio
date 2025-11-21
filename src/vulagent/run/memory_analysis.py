#!/usr/bin/env python3
"""Run the memory vulnerability detection workflow inside Docker.

- Builds a Docker sandbox (vulagent/memcheck) and copies the target project into /workspace/project/<name>.
- Loads the new mem_vuln.yaml config, instantiates DefaultAgent and model, and runs the analysis task.
- If the final report claims a vulnerability, automatically runs the reproduction command via run_verification.
- Saves everything (including verification metadata) with save_traj.
"""

from __future__ import annotations

import os
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console

from vulagent.config import get_config_path
from vulagent.agents.default import DefaultAgent
from vulagent.environments.docker import DockerEnvironment
from vulagent.models import get_model
from vulagent.run.utils import save_traj, run_verification

console = Console()
app = typer.Typer(rich_markup_mode="rich")

DEFAULT_CONFIG = "mem_vuln.yaml"
DEFAULT_DOCKER_IMAGE = "vulagent/memcheck:latest"
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
    config: str = typer.Option(
        DEFAULT_CONFIG,
        "--config",
        "-c",
        help="Agent config file (YAML) relative to config directory.",
    ),
    model: Optional[str] = typer.Option(
        None,
        "--model",
        "-m",
        help="Model name (defaults to MSWEA_MODEL_NAME env var or config).",
        prompt="Model name (leave blank to use default):",
    ),
    docker_image: str = typer.Option(
        DEFAULT_DOCKER_IMAGE,
        "--docker-image",
        help="Docker image to use for the sandbox environment.",
    ),
    output: Path | None = typer.Option(
        None,
        "--output",
        "-o",
        help="Where to store the resulting trajectory JSON (defaults to output/trajectory/<project>_traj_<timestamp>.json).",
    ),
    keep_container: bool = typer.Option(
        False,
        "--keep-container",
        help="Do not auto-remove container on exit (useful for debugging).",
    ),
) -> None:
    """Analyze *project_path* for memory-safety issues inside Docker."""

    project_path = project_path.resolve()
    if not project_path.exists():
        console.print(f"[bold red]Project path does not exist:[/bold red] {project_path}")
        raise typer.Exit(1)

    config_path = get_config_path(config)
    config_data = load_yaml(config_path)

    console.print(f"[bold green]Using config:[/bold green] {config_path}")

    model_name = model or os.getenv("MSWEA_MODEL_NAME")
    if not model_name:
        console.print("[bold red]No model specified.[/bold red] Set MSWEA_MODEL_NAME or use --model.")
        raise typer.Exit(1)

    console.print(f"[bold green]Model:[/bold green] {model_name}")
    console.print(f"[bold green]Docker image:[/bold green] {docker_image}")
    console.print(f"[bold green]Project path:[/bold green] {project_path}\n")

    # Prepare timestamped output paths
    # Use UTC to keep timestamps consistent across hosts
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    default_traj_dir = Path("output/trajectory")
    default_report_dir = Path("output/report")
    default_traj_dir.mkdir(parents=True, exist_ok=True)
    default_report_dir.mkdir(parents=True, exist_ok=True)

    output_path = output or default_traj_dir / f"{project_path.name}_traj_{timestamp}.json"


    workspace_project = PROJECT_ROOT / project_path.name
    run_args = ["--rm"] if not keep_container else []
    docker_env = DockerEnvironment(image=docker_image, cwd=str(workspace_project), run_args=run_args)

    try:
        copy_project_into_container(docker_env, project_path, workspace_project)

        env_config = config_data.get("environment", {})
        docker_env.config.env.update(env_config.get("env", {}))

        agent_config = config_data.get("agent", {})
        model_config = config_data.get("model", {})

        agent = DefaultAgent(
            get_model(model_name, model_config),
            docker_env,
            **agent_config,
        )

        task_description = (
            "Analyze the project for potential memory-safety issues and provide a reproduction command "
            "if a vulnerability is detected."
        )

        report_path_planned = default_report_dir / f"{project_path.name}_report_{timestamp}.md"
        console.print("[bold green]Starting agent...[/bold green]")
        console.print(f"[cyan]Trajectory will be written to:[/cyan] {output_path}")
        console.print(f"[cyan]Report will be written to:[/cyan] {report_path_planned}\n")
        started_at = datetime.now(timezone.utc)
        exit_status, result = agent.run(
            task_description,
            project_path=str(workspace_project),
        )
        finished_at = datetime.now(timezone.utc)
        copied_report: Path | None = None
        report_source = workspace_project / "final_report.md"
        report_destination = report_path_planned
        try:
            report_destination.parent.mkdir(parents=True, exist_ok=True)
            copied_report = docker_env.copy_from(report_source, report_destination)
            console.print(f"[bold green]Final report copied to:[/bold green] {copied_report}")
        except FileNotFoundError:
            console.print("[bold yellow]No final_report.md generated inside the container.[/bold yellow]")
        except RuntimeError as error:
            console.print(f"[bold red]Failed to copy final_report.md:[/bold red] {error}")

        verification = None
        if "status: vulnerable" in result.lower():
            console.print("\n[bold cyan]Attempting automatic verification...[/bold cyan]")
            reproduction_cmd = extract_reproduction_command(result)
            if reproduction_cmd:
                verification = run_verification(
                    docker_env,
                    reproduction_cmd,
                    cwd=str(workspace_project),
                )
                status = "successful" if verification.crash_detected else "failed"
                console.print(f"[bold cyan]Verification {status}.[/bold cyan]")
            else:
                console.print("[bold yellow]No reproduction command detected in final report.[/bold yellow]")

        info = {
            "exit_status": exit_status,
            "project_path": str(project_path),
            "docker_image": docker_image,
            "started_at_utc": started_at.isoformat(),
            "finished_at_utc": finished_at.isoformat(),
            "duration_seconds": (finished_at - started_at).total_seconds(),
        }
        if copied_report:
            info["final_report_path"] = str(copied_report)
        if verification:
            info["verification"] = verification.to_dict()

        output_path.parent.mkdir(parents=True, exist_ok=True)
        save_traj(agent, output_path, exit_status=exit_status, result=result, extra_info=info)
        console.print(f"\n[bold green]Trajectory saved to:[/bold green] {output_path}")

    finally:
        if not keep_container:
            docker_env.cleanup()


def copy_project_into_container(env: DockerEnvironment, project_path: Path, destination: Path) -> None:
    console.print("[yellow]Copying project into Docker workspace...[/yellow]")

    archive_cmd = [
        "tar",
        "-C",
        str(project_path.parent),
        "-cf",
        "-",
        project_path.name,
    ]

    extract_cmd = (
        f"mkdir -p {destination.parent} && rm -rf {destination} && "
        f"tar -C {destination.parent} -xf -"
    )

    with subprocess.Popen(archive_cmd, stdout=subprocess.PIPE) as tar_proc:
        exec_cmd = [
            env.config.executable,
            "exec",
            "-i",
            env.container_id,
            "bash",
            "-lc",
            extract_cmd,
        ]
        subprocess.run(exec_cmd, stdin=tar_proc.stdout, check=True)
        tar_proc.wait()
        if tar_proc.returncode != 0:
            raise RuntimeError("Failed to archive project for container copy")

    check_cmd = [
        env.config.executable,
        "exec",
        env.container_id,
        "bash",
        "-lc",
        f"if [ ! -d '{destination}' ]; then echo 'Destination missing'; exit 1; fi",
    ]
    subprocess.run(check_cmd, check=True)


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
