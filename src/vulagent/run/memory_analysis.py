#!/usr/bin/env python3
"""Run the memory vulnerability detection workflow inside Docker.

- Builds a Docker sandbox (vulagent/memcheck) and copies the target project into /workspace/project/<name>.
- Loads the new mem_vuln.yaml config, instantiates DefaultAgent and model, and runs the analysis task.
- If the final report claims a vulnerability, automatically runs the reproduction command via run_verification.
- Saves everything (including verification metadata) with save_traj.
"""

from __future__ import annotations

import os
import re
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


class LoggingConsole:
    """Wrapper that logs console output to both terminal and file."""

    def __init__(self, console: Console, log_path: Path | None = None):
        self.console = console
        self.log_file: Path | None = None
        self._file_handle = None
        if log_path:
            self.set_log_file(log_path)

    def set_log_file(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        self.log_file = path
        self._file_handle = open(path, "a", encoding="utf-8")

    def print(self, message: str, **kwargs) -> None:
        self.console.print(message, **kwargs)
        if self._file_handle:
            clean_msg = re.sub(r"\[/?[^\]]+\]", "", message)
            ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
            self._file_handle.write(f"{ts} | {clean_msg}\n")
            self._file_handle.flush()

    def close(self) -> None:
        if self._file_handle:
            self._file_handle.close()
            self._file_handle = None

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
        envvar="MSWEA_MODEL_NAME",
        help="Model name (set via --model or MSWEA_MODEL_NAME env var).",
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
        help="Where to store the trajectory JSON (defaults to output/<project>_<timestamp>/trajectory.json).",
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
    run_dir = Path("output") / f"{project_path.name}_{timestamp}"
    run_dir.mkdir(parents=True, exist_ok=True)

    output_path = output or run_dir / "trajectory.json"
    log_path = run_dir / "log.txt"

    log_console = LoggingConsole(console, log_path)
    console.print(f"[cyan]Run output directory:[/cyan] {run_dir}")

    workspace_project = PROJECT_ROOT / project_path.name
    run_args = ["--rm"] if not keep_container else []
    docker_env = DockerEnvironment(image=docker_image, cwd=str(workspace_project), run_args=run_args)

    try:
        copy_project_into_container(docker_env, project_path, workspace_project, log_console)

        env_config = config_data.get("environment", {})
        docker_env.config.env.update(env_config.get("env", {}))

        agent_config = config_data.get("agent", {})
        model_config = config_data.get("model", {})

        agent = DefaultAgent(
            get_model(model_name, model_config),
            docker_env,
            **agent_config,
        )
        # Add lightweight step logging so users see progress
        step_counter = {"n": 0}
        real_step = agent.step

        def step_with_progress():
            step_counter["n"] += 1
            log_console.print(f"[dim]Step {step_counter['n']}: querying/executing...[/dim]")
            return real_step()

        agent.step = step_with_progress

        task_description = (
            "Analyze the project for potential memory-safety issues and provide a reproduction command "
            "if a vulnerability is detected."
        )

        report_path_planned = run_dir / "report.md"
        poc_path_planned = run_dir / "poc"
        log_console.print("[bold green]Starting agent...[/bold green]\n")
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
            log_console.print(f"[bold green]Final report copied to:[/bold green] {copied_report}")
        except FileNotFoundError:
            log_console.print("[bold yellow]No final_report.md generated inside the container.[/bold yellow]")
        except RuntimeError as error:
            log_console.print(f"[bold red]Failed to copy final_report.md:[/bold red] {error}")

        copied_poc: Path | None = None
        poc_source = workspace_project / "poc"
        try:
            poc_path_planned.parent.mkdir(parents=True, exist_ok=True)
            copied_poc = docker_env.copy_from(poc_source, poc_path_planned)
            log_console.print(f"[bold green]PoC file copied to:[/bold green] {copied_poc}")
        except FileNotFoundError:
            log_console.print("[bold yellow]No poc file generated inside the container.[/bold yellow]")
        except RuntimeError as error:
            log_console.print(f"[bold red]Failed to copy poc file:[/bold red] {error}")

        verification = None
        if "status: vulnerable" in result.lower():
            log_console.print("\n[bold cyan]Attempting automatic verification...[/bold cyan]")
            reproduction_cmd = extract_reproduction_command(result)
            if reproduction_cmd:
                verification = run_verification(
                    docker_env,
                    reproduction_cmd,
                    cwd=str(workspace_project),
                )
                status = "successful" if verification.crash_detected else "failed"
                log_console.print(f"[bold cyan]Verification {status}.[/bold cyan]")
            else:
                log_console.print("[bold yellow]No reproduction command detected in final report.[/bold yellow]")

        info = {
            "exit_status": exit_status,
            "project_path": str(project_path),
            "docker_image": docker_image,
            "started_at_utc": started_at.isoformat(),
            "finished_at_utc": finished_at.isoformat(),
            "duration_seconds": (finished_at - started_at).total_seconds(),
            "run_dir": str(run_dir),
        }
        if copied_report:
            info["report_path"] = str(copied_report)
        if copied_poc:
            info["poc_path"] = str(copied_poc)
        if verification:
            info["verification"] = verification.to_dict()

        output_path.parent.mkdir(parents=True, exist_ok=True)
        save_traj(agent, output_path, exit_status=exit_status, result=result, extra_info=info)
        log_console.print(f"\n[bold green]Trajectory saved to:[/bold green] {output_path}")

    finally:
        log_console.close()
        if not keep_container:
            docker_env.cleanup()


def copy_project_into_container(env: DockerEnvironment, project_path: Path, destination: Path, log_console: LoggingConsole) -> None:
    log_console.print("[yellow]Copying project into Docker workspace...[/yellow]")

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
