#!/usr/bin/env python3
"""Run a file-targeted vulnerability scan inside Docker.

Copies a local folder into a Docker container and runs an agent
to find vulnerabilities in a specific target file.

Examples:
    vul-agent-file-scan -f ./my-project -t src/parser.c -m gpt-4o
"""

from __future__ import annotations

import json
import os
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import typer
import yaml
from rich.console import Console

from vulagent.agents.default import DefaultAgent
from vulagent.config import get_config_path
from vulagent.environments.docker import DockerEnvironment
from vulagent.models import get_model
from vulagent.run.utils import save_traj

console = Console()
app = typer.Typer(rich_markup_mode="rich")

DEFAULT_CONFIG = "agents/file_hypothesis.yaml"
DEFAULT_IMAGE = "vulagent/file-scan:latest"
PROJECT_ROOT = Path("/src")


def load_yaml(path: Path) -> dict:
    return yaml.safe_load(path.read_text()) or {}


def copy_folder_into_container(
    env: DockerEnvironment,
    folder_path: Path,
    destination: Path,
) -> None:
    """Copy a local folder into /src/ of the container using tar pipe."""
    archive_cmd = [
        "tar",
        "-C",
        str(folder_path.parent),
        "-cf",
        "-",
        folder_path.name,
    ]
    extract_cmd = (
        f"mkdir -p {destination} && rm -rf {destination}/* && "
        f"tar -C {destination} --strip-components=1 -xf -"
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
            raise RuntimeError("Failed to archive folder for container copy")

    # Verify destination exists
    check_cmd = [
        env.config.executable,
        "exec",
        env.container_id,
        "bash",
        "-lc",
        f"test -d '{destination}'",
    ]
    subprocess.run(check_cmd, check=True)


def copy_file_from_container(
    env: DockerEnvironment,
    source: Path,
    destination: Path,
    name: str,
) -> Path | None:
    """Copy a file from container, returning the destination path or None."""
    try:
        destination.parent.mkdir(parents=True, exist_ok=True)
        copied = env.copy_from(source, destination)
        console.print(f"[bold green]{name} copied to:[/bold green] {copied}")
        return copied
    except FileNotFoundError:
        console.print(f"[bold yellow]No {name} generated inside the container.[/bold yellow]")
        return None
    except RuntimeError as error:
        console.print(f"[bold red]Failed to copy {name}:[/bold red] {error}")
        return None


@app.command()
def main(
    folder_path: Path = typer.Option(
        ...,
        "--folder-path",
        "-f",
        help="Local folder to copy into the Docker container.",
    ),
    target_file: str = typer.Option(
        ...,
        "--target-file",
        "-t",
        help="Relative path to the file within the folder to analyze.",
    ),
    model: Optional[str] = typer.Option(
        None,
        "--model",
        "-m",
        envvar="MSWEA_MODEL_NAME",
        help="Model name (set via --model or MSWEA_MODEL_NAME env var).",
    ),
    config: str = typer.Option(
        DEFAULT_CONFIG,
        "--config",
        "-c",
        help="Agent config file (YAML) relative to config directory.",
    ),
    docker_image: str = typer.Option(
        DEFAULT_IMAGE,
        "--docker-image",
        help="Docker image to use.",
    ),
    output: Optional[Path] = typer.Option(
        None,
        "--output",
        "-o",
        help="Where to store the trajectory JSON.",
    ),
    keep_container: bool = typer.Option(
        False,
        "--keep-container",
        help="Do not auto-remove container on exit (useful for debugging).",
    ),
) -> None:
    """Scan a specific file in a project for vulnerabilities inside Docker."""
    # --- Validate inputs ---
    folder_path = folder_path.resolve()
    if not folder_path.is_dir():
        console.print(f"[bold red]Folder does not exist:[/bold red] {folder_path}")
        raise typer.Exit(1)

    target_in_folder = folder_path / target_file
    if not target_in_folder.is_file():
        console.print(f"[bold red]Target file does not exist:[/bold red] {target_in_folder}")
        raise typer.Exit(1)

    # --- Load config ---
    config_path = get_config_path(config)
    config_data = load_yaml(config_path)

    model_name = model or os.getenv("MSWEA_MODEL_NAME")
    if not model_name:
        console.print("[bold red]No model specified.[/bold red] Set MSWEA_MODEL_NAME or use --model.")
        raise typer.Exit(1)

    console.print(f"[bold green]Config:[/bold green] {config_path}")
    console.print(f"[bold green]Model:[/bold green] {model_name}")
    console.print(f"[bold green]Docker image:[/bold green] {docker_image}")
    console.print(f"[bold green]Folder:[/bold green] {folder_path}")
    console.print(f"[bold green]Target file:[/bold green] {target_file}")
    console.print()

    # --- Prepare output paths ---
    if output is not None:
        output_path = output
        run_dir = output_path.parent
    else:
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
        run_name = f"file-scan_{folder_path.name}_{timestamp}"
        run_dir = Path("output") / run_name
        output_path = run_dir / "trajectory.json"
    run_dir.mkdir(parents=True, exist_ok=True)

    console.print(f"[cyan]Run output directory:[/cyan] {run_dir}")

    # --- Start Docker container ---
    run_args = ["--rm"] if not keep_container else []
    env_config = config_data.get("environment", {})

    docker_env = DockerEnvironment(
        image=docker_image,
        cwd=str(PROJECT_ROOT),
        run_args=run_args,
        timeout=env_config.get("timeout", 120),
    )

    try:
        # Copy folder into container at /src/
        console.print("[yellow]Copying folder into Docker container...[/yellow]")
        copy_folder_into_container(docker_env, folder_path, PROJECT_ROOT)
        console.print("[bold green]Folder copied successfully.[/bold green]")

        # Set environment variables from config
        docker_env.config.env.update(env_config.get("env", {}))

        # --- Create and run agent ---
        agent_config = config_data.get("agent", {})
        model_config = config_data.get("model", {})

        # The YAML may place agent templates under the "model" key.
        # Move observation_template to agent_config (as action_observation_template)
        # and drop format_error_template (YAML version uses {{error}} which is
        # incompatible with DefaultAgent's {{actions}} variable).
        if "observation_template" in model_config:
            agent_config.setdefault(
                "action_observation_template", model_config.pop("observation_template")
            )
        model_config.pop("format_error_template", None)

        # Drop keys that AgentConfig doesn't recognise (e.g. "mode")
        for key in ("mode",):
            agent_config.pop(key, None)

        agent = DefaultAgent(
            get_model(model_name, model_config),
            docker_env,
            **agent_config,
        )

        task_description = (
            f"Analyze the file '{target_file}' in the project at {PROJECT_ROOT} "
            f"for security vulnerabilities."
        )

        console.print("[bold green]Starting agent...[/bold green]\n")
        started_at = datetime.now(timezone.utc)
        import platform
        exit_status, result = agent.run(
            task_description,
            project_path=str(PROJECT_ROOT),
            file_path=target_file,
            system=platform.system(),
        )
        finished_at = datetime.now(timezone.utc)

        console.print(f"\n[bold cyan]Exit status:[/bold cyan] {exit_status}")

        # --- Copy output files from container ---
        report_path = copy_file_from_container(
            docker_env,
            PROJECT_ROOT / "final_report.md",
            run_dir / "final_report.md",
            "final_report.md",
        )
        poc_path = copy_file_from_container(
            docker_env,
            PROJECT_ROOT / "poc",
            run_dir / "poc",
            "poc",
        )

        # --- Save trajectory ---
        info = {
            "exit_status": exit_status,
            "folder_path": str(folder_path),
            "target_file": target_file,
            "docker_image": docker_image,
            "started_at_utc": started_at.isoformat(),
            "finished_at_utc": finished_at.isoformat(),
            "duration_seconds": (finished_at - started_at).total_seconds(),
            "run_dir": str(run_dir),
        }
        if report_path:
            info["report_path"] = str(report_path)
        if poc_path:
            info["poc_path"] = str(poc_path)

        output_path.parent.mkdir(parents=True, exist_ok=True)
        save_traj(agent, output_path, exit_status=exit_status, result=result, extra_info=info)
        console.print(f"\n[bold green]Trajectory saved to:[/bold green] {output_path}")

    finally:
        if not keep_container:
            docker_env.cleanup()


if __name__ == "__main__":
    app()
