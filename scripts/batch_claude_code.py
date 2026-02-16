#!/usr/bin/env python3
"""Batch-run Claude Code on single-file CVEs that have repos downloaded.

For each CVE, starts a Docker container with the repo at /src, then invokes
Claude Code in non-interactive mode with a prompt to analyze the target file.
Claude Code uses `docker exec` to run commands inside the container.

Examples:
    # Dry-run: list matching CVEs
    python scripts/batch_claude_code.py -m opus --dry-run

    # Run one CVE only
    python scripts/batch_claude_code.py -m opus --limit 1

    # Run all with 4 workers
    python scripts/batch_claude_code.py -m opus --max-workers 4
"""

from __future__ import annotations

import json
import subprocess
import uuid
from concurrent.futures import ProcessPoolExecutor, as_completed
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console

console = Console()
app = typer.Typer(rich_markup_mode="rich", pretty_exceptions_show_locals=False)

SCRIPTS_DIR = Path(__file__).resolve().parent
DATASET_PATH = SCRIPTS_DIR / "cve_dataset.jsonl"
REPOS_DIR = SCRIPTS_DIR / "repos"
DOCKER_IMAGE = "vulagent/file-scan:latest"


def load_candidates(dataset: Path, repos_dir: Path) -> list[dict]:
    """Return single-file CVEs whose repo is downloaded."""
    candidates = []
    with open(dataset) as f:
        for line in f:
            entry = json.loads(line)
            if not entry.get("is_single_file"):
                continue
            cve_id = entry["cve_id"]
            repo_path = repos_dir / cve_id
            if not repo_path.is_dir():
                continue
            candidates.append({
                "cve_id": cve_id,
                "repo_path": str(repo_path),
                "target_file": entry["files"][0],
            })
    return candidates


def start_container(repo_path: str, docker_image: str) -> str:
    """Start a Docker container with the repo copied into /src. Returns container ID."""
    container_name = f"claude-scan-{uuid.uuid4().hex[:8]}"

    # Start container
    result = subprocess.run(
        ["docker", "run", "-d", "--name", container_name, "-w", "/src",
         docker_image, "sleep", "2h"],
        capture_output=True, text=True, timeout=120, check=True,
    )
    container_id = result.stdout.strip()

    # Copy repo into container via tar pipe
    repo = Path(repo_path)
    archive_cmd = ["tar", "-C", str(repo.parent), "-cf", "-", repo.name]
    extract_cmd = f"mkdir -p /src && rm -rf /src/* && tar -C /src --strip-components=1 -xf -"

    with subprocess.Popen(archive_cmd, stdout=subprocess.PIPE) as tar_proc:
        subprocess.run(
            ["docker", "exec", "-i", container_id, "bash", "-lc", extract_cmd],
            stdin=tar_proc.stdout, check=True,
        )
        tar_proc.wait()

    return container_id


def stop_container(container_id: str) -> None:
    """Stop and remove a container."""
    subprocess.Popen(
        f"(timeout 60 docker stop {container_id} || docker rm -f {container_id}) >/dev/null 2>&1",
        shell=True,
    )


PROMPT_TEMPLATE = """\
You have access to a Docker container (ID: {container_id}) that contains a C/C++ \
software repository at /src.

Your task: analyze the file `/src/{target_file}` for security vulnerabilities.

To run commands inside the container, use:
  docker exec {container_id} bash -c 'your_command'

## Workflow

1. Read and understand the target file and its dependencies.
2. Identify potential vulnerability sinks (buffer overflows, use-after-free, integer \
overflows, format string bugs, null pointer dereferences, etc.).
3. Trace data flow to determine if untrusted input can reach those sinks.
4. For each potential vulnerability, describe:
   - The vulnerable code location (file, function, line)
   - The type of vulnerability
   - How it could be triggered
   - A suggested fix

## Output

Produce a structured vulnerability report in markdown. If no vulnerabilities are found, \
state that clearly with your reasoning.

Focus on real, exploitable issues — not style or best-practice suggestions.\
"""


def run_one(
    cve_id: str,
    repo_path: str,
    target_file: str,
    model: str,
    max_turns: int,
    max_budget: float,
    docker_image: str,
    output_dir: Path,
    log_dir: Path,
) -> tuple[str, bool, str]:
    """Run Claude Code for a single CVE. Returns (cve_id, success, error)."""
    log_path = log_dir / f"{cve_id}.log"
    report_path = output_dir / cve_id / "report.json"
    report_path.parent.mkdir(parents=True, exist_ok=True)

    container_id = None
    try:
        container_id = start_container(repo_path, docker_image)
        prompt = PROMPT_TEMPLATE.format(container_id=container_id, target_file=target_file)

        cmd = [
            "claude",
            "-p", prompt,
            "--model", model,
            "--output-format", "json",
            "--max-turns", str(max_turns),
            "--allowedTools", f"Bash(docker exec {container_id}:*)",
        ]
        if max_budget > 0:
            cmd.extend(["--max-budget-usd", str(max_budget)])

        with open(log_path, "w") as log_file:
            result = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=log_file,
                timeout=3600,
                text=True,
            )

        report_path.write_text(result.stdout)

        if result.returncode != 0:
            return (cve_id, False, f"exit code {result.returncode}")
        return (cve_id, True, "")

    except subprocess.TimeoutExpired:
        return (cve_id, False, "timed out after 3600s")
    except Exception as e:
        return (cve_id, False, str(e))
    finally:
        if container_id:
            stop_container(container_id)


@app.command()
def main(
    model: str = typer.Option(
        "opus",
        "--model",
        "-m",
        help="Claude Code model (opus, sonnet, etc.).",
    ),
    max_workers: int = typer.Option(
        4,
        "--max-workers",
        "-w",
        help="Maximum number of parallel workers.",
    ),
    max_turns: int = typer.Option(
        1000000,
        "--max-turns",
        help="Max agentic turns per CVE.",
    ),
    max_budget: float = typer.Option(
        10.0,
        "--max-budget",
        help="Max USD budget per CVE (0 = unlimited).",
    ),
    limit: Optional[int] = typer.Option(
        None,
        "--limit",
        "-l",
        help="Only run this many CVEs (useful for testing).",
    ),
    batch_id: str = typer.Option(
        "batch_claude_code",
        "--batch-id",
        "-b",
        help="Batch identifier used as the output subdirectory name.",
    ),
    output_dir: Optional[Path] = typer.Option(
        None,
        "--output-dir",
        "-o",
        help="Base output directory (overrides --batch-id if set).",
    ),
    docker_image: str = typer.Option(
        DOCKER_IMAGE,
        "--docker-image",
        help="Docker image to use.",
    ),
    dry_run: bool = typer.Option(
        False,
        "--dry-run",
        help="List matching CVEs without running.",
    ),
    dataset: Path = typer.Option(
        DATASET_PATH,
        "--dataset",
        help="Path to cve_dataset.jsonl.",
    ),
    repos_dir: Path = typer.Option(
        REPOS_DIR,
        "--repos-dir",
        help="Directory containing downloaded repos.",
    ),
) -> None:
    """Batch-run Claude Code file analysis on single-file CVEs."""
    resolved_output_dir = output_dir or Path("output") / batch_id

    candidates = load_candidates(dataset, repos_dir)

    if not candidates:
        console.print("[bold red]No matching CVEs found.[/bold red]")
        raise typer.Exit(1)

    # Skip CVEs that already have output
    before = len(candidates)
    candidates = [c for c in candidates if not (resolved_output_dir / c["cve_id"]).exists()]
    skipped = before - len(candidates)

    if limit is not None:
        candidates = candidates[:limit]

    console.print(f"[bold green]Batch ID:[/bold green] {batch_id}")
    console.print(f"[bold green]Output dir:[/bold green] {resolved_output_dir}")
    console.print(f"[bold green]Matched CVEs:[/bold green] {before}")
    if skipped:
        console.print(f"[bold yellow]Skipped (already exist):[/bold yellow] {skipped}")
    console.print(f"[bold green]To run:[/bold green] {len(candidates)}")
    console.print(f"[bold green]Model:[/bold green] {model}")
    console.print(f"[bold green]Max turns:[/bold green] {max_turns}")
    console.print(f"[bold green]Max budget:[/bold green] ${max_budget:.2f}")
    console.print(f"[bold green]Workers:[/bold green] {max_workers}")
    console.print()

    if not candidates:
        console.print("[cyan]Nothing to run — all CVEs already processed.[/cyan]")
        return

    if dry_run:
        for c in candidates:
            console.print(f"  {c['cve_id']}: {c['target_file']}")
        console.print(f"\n[cyan]Total: {len(candidates)} (dry run, nothing executed)[/cyan]")
        return

    log_dir = resolved_output_dir / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    resolved_output_dir.mkdir(parents=True, exist_ok=True)

    total = len(candidates)
    completed = 0
    successful = 0
    failed = 0

    console.print(f"[bold cyan]Submitting {total} tasks...[/bold cyan]\n")

    with ProcessPoolExecutor(max_workers=max_workers) as executor:
        future_to_cve = {
            executor.submit(
                run_one,
                c["cve_id"],
                c["repo_path"],
                c["target_file"],
                model,
                max_turns,
                max_budget,
                docker_image,
                resolved_output_dir,
                log_dir,
            ): c
            for c in candidates
        }

        for future in as_completed(future_to_cve):
            c = future_to_cve[future]
            completed += 1

            try:
                cve_id, success, error_msg = future.result()
                if success:
                    successful += 1
                    console.print(
                        f"[bold green]  ({completed}/{total}) {cve_id}[/bold green] "
                        f"[dim]{c['target_file']}[/dim]"
                    )
                else:
                    failed += 1
                    console.print(
                        f"[bold red]  ({completed}/{total}) {cve_id}: {error_msg}[/bold red]"
                    )
            except Exception as e:
                failed += 1
                console.print(
                    f"[bold red]  ({completed}/{total}) {c['cve_id']}: {e}[/bold red]"
                )

    console.print(f"\n[bold green]Batch complete.[/bold green]")
    console.print(f"  Total:      {total}")
    console.print(f"  Successful: {successful}")
    console.print(f"  Failed:     {failed}")
    console.print(f"  Output:     {resolved_output_dir}")
    console.print(f"  Logs:       {log_dir}")


if __name__ == "__main__":
    app()
