#!/usr/bin/env python3
"""Run the vulnerability detection workflow inside Docker.

Supports multiple target sources:
- ARVO: Pre-built Docker images with fuzzing infrastructure (--arvo)
- Custom projects: Local projects copied into container (--project)

Examples:
    # ARVO target
    python -m vulagent.run.detect --arvo n132/arvo:42470801-vul

    # Custom project
    python -m vulagent.run.detect --project ./examples/bof
"""

from __future__ import annotations

import json
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
from vulagent.artifacts.store import ArtifactStore
from vulagent.environments.docker import DockerEnvironment
from vulagent.run.clean_arvo import CLEANUP_COMMANDS
from vulagent.models import get_model
from vulagent.orchestrator import MultiAgentOrchestrator, default_agent_specs
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


DEFAULT_CONFIG = "vuln.yaml"
ARVO_TARGETS_FILE = "arvo_targets.json"
WORKSPACE_ROOT = Path("/")
PROJECT_ROOT = WORKSPACE_ROOT / "src"
DEFAULT_AGENTS_DIR = Path(__file__).resolve().parent.parent / "config" / "agents"


def load_arvo_targets() -> list[str]:
    """Load the list of valid ARVO target images."""
    targets_path = get_config_path(ARVO_TARGETS_FILE)
    if targets_path.exists():
        return json.loads(targets_path.read_text())
    return []


def get_run_name(arvo_image: str | None, project_path: Path | None) -> str:
    """Generate a run name based on the target source."""
    if arvo_image:
        # Extract tag from image name: n132/arvo:42470801-vul -> arvo-42470801-vul
        tag = arvo_image.split(":")[-1] if ":" in arvo_image else arvo_image
        return f"arvo-{tag}"
    elif project_path:
        return project_path.name
    return "unknown"


@app.command()
def main(
    arvo: Optional[str] = typer.Option(
        None,
        "--arvo",
        "-a",
        help="ARVO Docker image (e.g., n132/arvo:42470801-vul).",
    ),
    project_path: Optional[Path] = typer.Option(
        None,
        "--project",
        "-p",
        help="Path to a local software project to analyse.",
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
    docker_image: Optional[str] = typer.Option(
        None,
        "--docker-image",
        help="Docker image for custom projects (ignored when using --arvo).",
    ),
    output: Path | None = typer.Option(
        None,
        "--output",
        "-o",
        help="Where to store the trajectory JSON (defaults to output/<target>_<timestamp>/trajectory.json).",
    ),
    keep_container: bool = typer.Option(
        False,
        "--keep-container",
        help="Do not auto-remove container on exit (useful for debugging).",
    ),
    multi_agent: bool = typer.Option(
        True,
        "--multi-agent/--single-agent",
        help="Use multi-agent pipeline (default) or legacy single-agent workflow.",
    ),
    agents_config_dir: Optional[Path] = typer.Option(
        None,
        "--agents-config-dir",
        help="Directory containing per-agent YAML configs (default: config/agents).",
    ),
    max_poc_attempts: int = typer.Option(
        2,
        "--max-poc-attempts",
        help="Max PoC attempts per hypothesis in multi-agent mode.",
    ),
    top_n: int = typer.Option(
        5,
        "--top-n",
        help="Number of hypotheses to generate in the first (hypothesis) stage of multi-agent mode.",
    ),
) -> None:
    """Analyze a target for software vulnerabilities inside Docker.

    Use --arvo for ARVO targets or --project for custom local projects.
    """
    # Validate mutually exclusive options
    if arvo and project_path:
        console.print("[bold red]Cannot specify both --arvo and --project.[/bold red]")
        raise typer.Exit(1)

    if not arvo and not project_path:
        console.print("[bold red]Must specify either --arvo or --project.[/bold red]")
        console.print("Examples:")
        console.print("  python -m vulagent.run.detect --arvo n132/arvo:42470801-vul")
        console.print("  python -m vulagent.run.detect --project ./examples/bof")
        raise typer.Exit(1)

    # Determine mode and validate
    arvo_mode = arvo is not None

    if arvo_mode:
        # Validate ARVO image format
        if ":" not in arvo:
            console.print(f"[bold red]Invalid ARVO image format:[/bold red] {arvo}")
            console.print("Expected format: n132/arvo:<tag> (e.g., n132/arvo:42470801-vul)")
            raise typer.Exit(1)
        image = arvo
        run_name = get_run_name(arvo, None)
    else:
        project_path = project_path.resolve()
        if not project_path.exists():
            console.print(f"[bold red]Project path does not exist:[/bold red] {project_path}")
            raise typer.Exit(1)
        image = docker_image or "vulagent/memcheck:latest"
        run_name = get_run_name(None, project_path)

    config_path = get_config_path(config)
    config_data = load_yaml(config_path)

    console.print(f"[bold green]Using config:[/bold green] {config_path}")

    model_name = model or os.getenv("MSWEA_MODEL_NAME")
    if not model_name:
        console.print("[bold red]No model specified.[/bold red] Set MSWEA_MODEL_NAME or use --model.")
        raise typer.Exit(1)

    console.print(f"[bold green]Model:[/bold green] {model_name}")
    console.print(f"[bold green]Docker image:[/bold green] {image}")
    if arvo_mode:
        console.print("[bold green]Mode:[/bold green] ARVO")
    else:
        console.print(f"[bold green]Project path:[/bold green] {project_path}")
    console.print()

    # Prepare timestamped output paths
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    run_id = f"{run_name}_{timestamp}"
    store = ArtifactStore(Path("output"), run_id=run_id)
    run_dir = store.run_dir

    output_path = output or run_dir / "trajectory.json"
    log_path = run_dir / "log.txt"

    log_console = LoggingConsole(console, log_path)
    console.print(f"[cyan]Run output directory:[/cyan] {run_dir}")

    workspace_project = PROJECT_ROOT
    run_args = ["--rm"] if not keep_container else []
    env_config = config_data.get("environment", {})

    docker_env = DockerEnvironment(
        image=image,
        cwd=str(workspace_project),
        run_args=run_args,
        timeout=env_config.get("timeout", 120),
        post_start_commands=CLEANUP_COMMANDS if arvo_mode else [],
    )

    try:
        # For custom projects, copy files into container
        # For ARVO, source code is already in the image
        if not arvo_mode:
            copy_project_into_container(docker_env, project_path, workspace_project, log_console)

        docker_env.config.env.update(env_config.get("env", {}))

        store.save_manifest(
            {
                "run_id": store.run_id,
                "target_type": "arvo" if arvo_mode else "project",
                "target_ref": arvo if arvo_mode else str(project_path),
                "created_at_utc": datetime.now(timezone.utc).isoformat(),
                "config_path": str(config_path),
                "model_name": model_name,
                "pipeline": "multi-agent" if multi_agent else "single-agent",
                "top_n": top_n if multi_agent else None,
            }
        )

        if multi_agent:
            agents_dir = agents_config_dir or DEFAULT_AGENTS_DIR
            specs = default_agent_specs(agents_dir)
            if not specs["hypothesis"].config_path.exists():
                console.print(
                    f"[bold red]Missing hypothesis agent config:[/bold red] {specs['hypothesis'].config_path}\n"
                    "Your agents config directory must include hypothesis.yaml (combined review+hypotheses stage)."
                )
                raise typer.Exit(1)

            log_console.print("[bold green]Starting multi-agent orchestrator...[/bold green]\n")
            started_at = datetime.now(timezone.utc)

            copied_during_run = True

            def copy_on_success(*, hypothesis_id: str, report_path: str, poc_path: str, script_path: str) -> None:
                dest_dir = store.layout.deliverables_dir
                for path, atype in [
                    (report_path, "BugReportFile"),
                    (poc_path, "PoCInput"),
                    (script_path, "PoCGenerator"),
                ]:
                    if not path:
                        continue
                    copied = copy_file_from_container(
                        docker_env, workspace_project / path, dest_dir / Path(path).name, path, log_console,
                    )
                    if copied:
                        store.register_artifact(copied, artifact_type=atype)

            orchestrator = MultiAgentOrchestrator(
                store=store,
                env=docker_env,
                model_name=model_name,
                model_config=config_data.get("model", {}),
                project_path=str(workspace_project),
                arvo_mode=arvo_mode,
                top_n=top_n,
                max_poc_attempts=max_poc_attempts,
                log_fn=log_console.print,
                on_success=copy_on_success,
            )
            result = orchestrator.run(
                hypothesis=specs["hypothesis"],
                poc_builder=specs["poc_builder"],
                validator=specs["validator"],
                reporter=specs["reporter"],
            )
            finished_at = datetime.now(timezone.utc)
            log_console.print(f"[bold cyan]Run status:[/bold cyan] {result.status}")

            if not copied_during_run:
                dest_dir = store.layout.deliverables_dir
                for name, atype in [
                    *[(n, "BugReportFile") for n in (result.report_paths or [])],
                    *[(n, "PoCInput") for n in (result.poc_paths or [])],
                    *[(n, "PoCGenerator") for n in (result.script_paths or [])],
                ]:
                    copied = copy_file_from_container(
                        docker_env, workspace_project / name, dest_dir / Path(name).name, name, log_console,
                    )
                    if copied:
                        store.register_artifact(copied, artifact_type=atype)

            log_console.print(f"\n[bold green]Trajectory saved to:[/bold green] {store.aggregated_trajectory_path}")

        else:
            agent_config = config_data.get("agent", {})
            model_config = config_data.get("model", {})

            agent = DefaultAgent(
                get_model(model_name, model_config),
                docker_env,
                **agent_config,
            )

            # Add lightweight step logging
            step_counter = {"n": 0}
            real_step = agent.step

            def step_with_progress():
                step_counter["n"] += 1
                log_console.print(f"[dim]Step {step_counter['n']}: querying/executing...[/dim]")
                return real_step()

            agent.step = step_with_progress

            task_description = (
                "Analyze the project for potential memory-safety issues and provide a reproduction command if a vulnerability is detected."
            )

            report_path_planned = run_dir / "report.md"
            poc_path_planned = run_dir / "poc"
            log_console.print("[bold green]Starting agent...[/bold green]\n")
            started_at = datetime.now(timezone.utc)
            exit_status, result = agent.run(
                task_description,
                project_path=str(workspace_project),
                arvo_mode=arvo_mode,
            )
            finished_at = datetime.now(timezone.utc)

            # Parse structured task result from agent output
            task_result = parse_task_result(result)
            log_console.print(f"[bold cyan]Task status:[/bold cyan] {task_result.get('status', 'unknown')}")
            if task_result.get("analysis"):
                log_console.print(f"[dim]Analysis: {task_result['analysis'][:200]}...[/dim]")

            # Copy output files from container (only on success)
            copied_report: Path | None = None
            copied_poc: Path | None = None
            copied_script: Path | None = None
            if task_result.get("status") == "success":
                copied_report = copy_file_from_container(
                    docker_env, workspace_project / "final_report.md",
                    report_path_planned, "final_report.md", log_console
                )
                copied_poc = copy_file_from_container(
                    docker_env, workspace_project / "poc",
                    poc_path_planned, "poc", log_console
                )
                script_path_planned = run_dir / "result_script.py"
                copied_script = copy_file_from_container(
                    docker_env, workspace_project / "result_script.py",
                    script_path_planned, "result_script.py", log_console
                )

            verification = None
            if task_result.get("status") == "success":
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
                "task_status": task_result.get("status", "unknown"),
                "arvo_image": arvo if arvo_mode else None,
                "project_path": str(project_path) if project_path else None,
                "docker_image": image,
                "arvo_mode": arvo_mode,
                "started_at_utc": started_at.isoformat(),
                "finished_at_utc": finished_at.isoformat(),
                "duration_seconds": (finished_at - started_at).total_seconds(),
                "run_dir": str(run_dir),
            }
            if task_result.get("analysis"):
                info["analysis"] = task_result["analysis"]
            if copied_report:
                info["report_path"] = str(copied_report)
            if copied_poc:
                info["poc_path"] = str(copied_poc)
            if copied_script:
                info["result_script_path"] = str(copied_script)
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


def parse_task_result(result: str) -> dict[str, str]:
    """Parse structured task result from finish tool output (YAML format).

    Expected format (YAML):
        status: success
        analysis: Brief analysis...
        result_script: result_script.py
        poc: poc
        report: final_report.md
    """
    import yaml

    try:
        parsed = yaml.safe_load(result)
        if isinstance(parsed, dict):
            return {k: str(v) for k, v in parsed.items()}
    except yaml.YAMLError:
        pass
    return {}


def copy_file_from_container(
    env: DockerEnvironment,
    source: Path,
    destination: Path,
    name: str,
    log_console: LoggingConsole,
) -> Path | None:
    """Copy a file from container, returning the destination path or None."""
    try:
        destination.parent.mkdir(parents=True, exist_ok=True)
        copied = env.copy_from(source, destination)
        log_console.print(f"[bold green]{name} copied to:[/bold green] {copied}")
        return copied
    except FileNotFoundError:
        log_console.print(f"[bold yellow]No {name} generated inside the container.[/bold yellow]")
        return None
    except RuntimeError as error:
        log_console.print(f"[bold red]Failed to copy {name}:[/bold red] {error}")
        return None


if __name__ == "__main__":
    app()
