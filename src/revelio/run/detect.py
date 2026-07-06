#!/usr/bin/env python3
"""Run the vulnerability detection workflow inside Docker.

Supports multiple target sources:
- ARVO: Pre-built Docker images with fuzzing infrastructure (--arvo)
- Custom projects: Local projects copied into container (--project)

Examples:
    # ARVO target
    python -m revelio.run.detect --arvo n132/arvo:42470801-vul

    # Custom project
    python -m revelio.run.detect --project ./examples/bof
"""

from __future__ import annotations

import json
import os
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

import typer
from rich.console import Console

from revelio.artifacts.schema import CodeReference, VulnHypotheses, VulnHypothesis
from revelio.artifacts.store import ArtifactStore
from revelio.environments.docker import DockerEnvironment
from revelio.orchestrator import MultiAgentOrchestrator, default_agent_specs
from revelio.run.clean_arvo import CLEANUP_COMMANDS

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


WORKSPACE_ROOT = Path("/")
PROJECT_ROOT = WORKSPACE_ROOT / "src"
DEFAULT_AGENTS_DIR = Path(__file__).resolve().parent.parent / "config" / "agents"
DEFAULT_DOCKER_TIMEOUT = 300
DEFAULT_DOCKER_ENV = {
    "PAGER": "cat",
    "LESS": "-R",
    "ASAN_OPTIONS": "detect_leaks=0:halt_on_error=1:abort_on_error=1",
    "UBSAN_OPTIONS": "print_stacktrace=1",
}



def get_run_name(arvo_image: str | None, project_path: Path | None) -> str:
    """Generate a run name based on the target source.

    For Docker images, take everything after the last '/' (i.e. drop the
    registry/namespace prefix) and replace ':' with '-' so the project name is
    preserved in the run id. Examples:
        revelio/openssl:latest       -> openssl-latest
        n132/arvo:42470801-vul        -> arvo-42470801-vul
        arvo:latest                   -> arvo-latest
    """
    if arvo_image:
        name = arvo_image.rsplit("/", 1)[-1]
        return name.replace(":", "-")
    elif project_path:
        return project_path.name
    return "unknown"


def save_hypotheses(hypotheses: VulnHypotheses, path: Path) -> Path:
    """Save hypotheses to a standalone JSON file for later reuse."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(hypotheses.to_dict(), indent=2))
    return path


def _hypotheses_from_items(items: list[dict[str, Any]]) -> list[VulnHypothesis]:
    """Build VulnHypothesis objects from a list of dicts (payload/file format).

    Accepts both the new schema (with severity/primitive/attacker_controls/
    sanitizers/cwe_ids/reachable/fuzz_targets) and older files that lack those
    fields. Unknown fields default to the dataclass defaults.
    """
    hyps: list[VulnHypothesis] = []
    for h in items:
        refs = [
            CodeReference(
                file_path=r["file_path"],
                line_start=r.get("line_start"),
                line_end=r.get("line_end"),
                function=r.get("function"),
                context=r.get("context"),
            )
            for r in h.get("references", [])
        ]
        reachable = h.get("reachable")
        hyps.append(VulnHypothesis(
            hypothesis_id=h["hypothesis_id"],
            title=h["title"],
            description=h["description"],
            file_path=h.get("file_path"),
            function=h.get("function"),
            trigger=h.get("trigger"),
            preconditions=h.get("preconditions", []),
            expected_crash=h.get("expected_crash"),
            confidence=h.get("confidence", 0.0),
            references=refs,
            severity=h.get("severity", "none"),
            primitive=h.get("primitive", "none"),
            attacker_controls=h.get("attacker_controls", "none"),
            sanitizers=list(h.get("sanitizers", [])),
            cwe_ids=[str(c) for c in h.get("cwe_ids", [])],
            reachable=(bool(reachable) if reachable is not None else None),
            fuzz_targets=list(h.get("fuzz_targets", [])),
        ))
    return hyps


def load_hypotheses(path: Path) -> VulnHypotheses:
    """Load hypotheses from a previously saved JSON file.

    Accepts both standalone format (from save_hypotheses) and
    handoff-wrapped format (from ArtifactStore.write_handoff).
    """
    data = json.loads(path.read_text())
    # Unwrap handoff envelope if present
    if "data" in data and "hypotheses" in data["data"]:
        data = data["data"]
    return VulnHypotheses(
        hypotheses=_hypotheses_from_items(data.get("hypotheses", [])),
        generation_notes=data.get("generation_notes"),
    )



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
    model: Optional[str] = typer.Option(
        None,
        "--model",
        envvar="MODEL_NAME",
        help="Model name (set via --model or MODEL_NAME env var).",
    ),
    docker_image: Optional[str] = typer.Option(
        None,
        "--docker-image",
        help="Docker image for custom projects (ignored when using --arvo).",
    ),
    keep_container: bool = typer.Option(
        False,
        "--keep-container",
        help="Do not auto-remove container on exit (useful for debugging).",
    ),
    target_file: Optional[str] = typer.Option(
        None,
        "--target-file",
        "-t",
        help="Target file path (relative to project root). Restricts scan to a single file.",
    ),
    max_workers: int = typer.Option(
        4,
        "--max-workers",
        help="Number of parallel workers for hypothesis generation.",
    ),
    agents_config_dir: Optional[Path] = typer.Option(
        None,
        "--agents-config-dir",
        help="Directory containing per-agent YAML configs (default: config/agents).",
    ),
    max_poc_attempts: int = typer.Option(
        3,
        "--max-poc-attempts",
        help="Max PoC attempts per hypothesis in multi-agent mode.",
    ),
    top_n: int = typer.Option(
        10,
        "--top-n",
        help="Number of hypotheses to generate in the first (hypothesis) stage of multi-agent mode.",
    ),
    filter_model: Optional[str] = typer.Option(
        "litellm_proxy/vertex_ai/claude-sonnet-4-6",
        "--filter-model",
        help="Model for scan_filter Stage 3 sub-agent verification (default: Sonnet 4.6).",
    ),
    filter_workers: int = typer.Option(
        4,
        "--filter-workers",
        help="Parallel workers for scan_filter sub-agent filtering.",
    ),
    max_functions: int = typer.Option(
        50,
        "--max-functions",
        help="Max functions to analyze per file in scan_filter mode.",
    ),
    agent_step_limit: int = typer.Option(
        20,
        "--agent-step-limit",
        help="Max steps per scan_filter sub-agent.",
    ),
    agent_cost_limit: float = typer.Option(
        2.0,
        "--agent-cost-limit",
        help="Max cost per scan_filter sub-agent.",
    ),
    base_url: Optional[str] = typer.Option(
        None,
        "--base-url",
        help="LiteLLM proxy base URL (used by scan_filter modes).",
    ),
    api_key: Optional[str] = typer.Option(
        None,
        "--api-key",
        envvar="MODEL_API_KEY",
        help="API key for LLM calls (used by scan_filter modes).",
    ),
    poc_model: Optional[str] = typer.Option(
        None,
        "--poc-model",
        help="Model for PoC/validator/reporter agents (default: same as --model).",
    ),
    hypotheses_file: Optional[Path] = typer.Option(
        None,
        "--hypotheses-file",
        help="Load pre-generated hypotheses from JSON file (skip scan_filter, go straight to PoC).",
    ),
) -> None:
    """Analyze a target for software vulnerabilities inside Docker.

    Use --arvo for ARVO targets or --project for custom local projects.
    """
    if arvo and project_path:
        console.print("[bold red]Cannot specify both --arvo and --project.[/bold red]")
        raise typer.Exit(1)

    if not arvo and not project_path:
        console.print("[bold red]Must specify either --arvo or --project.[/bold red]")
        console.print("Examples:")
        console.print("  python -m revelio.run.detect --arvo n132/arvo:42470801-vul")
        console.print("  python -m revelio.run.detect --project ./examples/bof")
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
        image = docker_image or "revelio/memcheck:latest"
        run_name = get_run_name(None, project_path)

    model_name = model or os.getenv("MODEL_NAME")
    if not model_name:
        console.print("[bold red]No model specified.[/bold red] Set MODEL_NAME or use --model.")
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
    model_slug = model_name.replace("/", "_").replace(":", "_")
    run_id = f"{run_name}_{model_slug}_{timestamp}"
    store = ArtifactStore(Path("output"), run_id=run_id)
    run_dir = store.run_dir

    log_path = run_dir / "log.txt"

    log_console = LoggingConsole(console, log_path)
    console.print(f"[cyan]Run output directory:[/cyan] {run_dir}")

    workspace_project = PROJECT_ROOT
    run_args = ["--rm"] if not keep_container else []

    docker_env = DockerEnvironment(
        image=image,
        cwd=str(workspace_project),
        run_args=run_args,
        timeout=DEFAULT_DOCKER_TIMEOUT,
        post_start_commands=CLEANUP_COMMANDS if arvo_mode else [],
    )

    try:
        # For custom projects, copy files into container
        # For ARVO, source code is already in the image
        if not arvo_mode:
            copy_project_into_container(docker_env, project_path, workspace_project, log_console)

        docker_env.config.env.update(DEFAULT_DOCKER_ENV)

        effective_filter_model = filter_model or model_name
        effective_poc_model = poc_model or model_name
        store.save_manifest(
            {
                "run_id": store.run_id,
                "target_type": "arvo" if arvo_mode else "project",
                "target_ref": arvo if arvo_mode else str(project_path),
                "created_at_utc": datetime.now(timezone.utc).isoformat(),
                "model_name": model_name,
                "filter_model": effective_filter_model,
                "poc_model": effective_poc_model,
                "pipeline": "scan_filter_detect",
                "top_n": top_n,
                "target_file": target_file if target_file else None,
                "max_workers": max_workers,
            }
        )

        if hypotheses_file:
            if not hypotheses_file.exists():
                log_console.print(f"[bold red]Hypotheses file not found:[/bold red] {hypotheses_file}")
                raise typer.Exit(1)
            hypotheses = load_hypotheses(hypotheses_file)
            log_console.print(
                f"[bold cyan]Loaded {len(hypotheses.hypotheses)} hypotheses from:[/bold cyan] {hypotheses_file}"
            )
            store.write_handoff("hypotheses", hypotheses)
        else:
            from revelio.orchestrator.scan_filter import ScanFilterOrchestrator

            scan_model_kwargs: dict = {"temperature": 1.0, "drop_params": True}
            if base_url:
                scan_model_kwargs["base_url"] = base_url
            if api_key:
                scan_model_kwargs["api_key"] = api_key

            scan_orch = ScanFilterOrchestrator(
                env=docker_env,
                model_name=model_name,
                store=store,
                log_fn=log_console.print,
                max_workers=max_workers,
                filter_model=filter_model,
                filter_workers=filter_workers,
                max_functions=max_functions,
                agent_step_limit=agent_step_limit,
                agent_cost_limit=agent_cost_limit,
                model_kwargs=scan_model_kwargs,
            )

            log_console.print(f"[bold green]Starting scan_filter...[/bold green]\n")
            started_at = datetime.now(timezone.utc)
            hypotheses = scan_orch.run(
                project_path=str(workspace_project),
                arvo_mode=arvo_mode,
                target_file=target_file,
            )
            elapsed = (datetime.now(timezone.utc) - started_at).total_seconds()
            log_console.print(
                f"[bold cyan]Scan-filter complete:[/bold cyan] "
                f"{len(hypotheses.hypotheses)} hypotheses "
                f"({elapsed:.1f}s) — {hypotheses.generation_notes or ''}"
            )
            store.write_handoff("hypotheses", hypotheses)
            hyp_path = save_hypotheses(hypotheses, run_dir / "hypotheses.json")
            log_console.print(
                f"[bold green]Hypotheses saved to:[/bold green] {hyp_path}\n"
                f"  Reuse later with: --hypotheses-file {hyp_path}"
            )

        if not hypotheses.hypotheses:
            log_console.print("[bold yellow]No hypotheses survived filtering.[/bold yellow]")
        else:
            agents_dir = agents_config_dir or DEFAULT_AGENTS_DIR
            specs = default_agent_specs(agents_dir)

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

            model_config: dict = {}
            if base_url:
                model_config.setdefault("model_kwargs", {})["base_url"] = base_url
            if api_key:
                model_config.setdefault("model_kwargs", {})["api_key"] = api_key

            orchestrator = MultiAgentOrchestrator(
                store=store,
                env=docker_env,
                model_name=poc_model or model_name,
                project_path=str(workspace_project),
                arvo_mode=arvo_mode,
                top_n=top_n,
                max_poc_attempts=max_poc_attempts,
                log_fn=log_console.print,
                on_success=copy_on_success,
                max_workers=max_workers,
                hypotheses_override=hypotheses,
                model_config=model_config,
            )
            result = orchestrator.run(
                poc_builder=specs["poc_builder"],
                reporter=specs["reporter"],
            )
            log_console.print(f"[bold cyan]Run status:[/bold cyan] {result.status}")
            log_console.print(f"\n[bold green]Trajectory saved to:[/bold green] {store.aggregated_trajectory_path}")

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
