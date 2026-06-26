#!/usr/bin/env python3
"""Batch-run revelio-file-scan on single-file CVEs that have repos downloaded.

Reads scripts/cve_dataset.jsonl, filters to single-file CVEs whose repo exists
in scripts/repos/<CVE-ID>/, and launches revelio-file-scan concurrently.

Examples:
    # Dry-run: list matching CVEs without running
    python scripts/batch_file_scan.py --model claude-opus-4-6 --dry-run

    # Run one CVE only
    python scripts/batch_file_scan.py --model claude-opus-4-6 --limit 1

    # Run all with 4 workers
    python scripts/batch_file_scan.py --model claude-opus-4-6 --max-workers 4
"""

from __future__ import annotations

import json
import subprocess
import sys
from concurrent.futures import ProcessPoolExecutor, as_completed
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console

console = Console()
app = typer.Typer(rich_markup_mode="rich", pretty_exceptions_show_locals=False)

SCRIPTS_DIR = Path("/srv/share/revelio/")
DATASET_PATH = SCRIPTS_DIR / "cve_dataset.jsonl"
REPOS_DIR = SCRIPTS_DIR / "repos"


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


def run_one(
    cve_id: str,
    repo_path: str,
    target_file: str,
    model: str,
    config: str,
    docker_image: str,
    output_dir: Path,
    log_dir: Path,
) -> tuple[str, bool, str]:
    """Run revelio-file-scan for a single CVE. Returns (cve_id, success, error)."""
    out_path = output_dir / cve_id / "trajectory.json"
    log_path = log_dir / f"{cve_id}.log"
    log_path.parent.mkdir(parents=True, exist_ok=True)

    cmd = [
        sys.executable, "-m", "revelio.run.file_scan",
        "--folder-path", repo_path,
        "--target-file", target_file,
        "--model", model,
        "--config", config,
        "--docker-image", docker_image,
        "--output", str(out_path),
    ]

    try:
        with open(log_path, "w") as log_file:
            result = subprocess.run(
                cmd,
                stdout=log_file,
                stderr=subprocess.STDOUT,
                timeout=3600,
            )
        if result.returncode != 0:
            return (cve_id, False, f"exit code {result.returncode}")
        return (cve_id, True, "")
    except subprocess.TimeoutExpired:
        return (cve_id, False, "timed out after 3600s")
    except Exception as e:
        return (cve_id, False, str(e))


@app.command()
def main(
    model: str = typer.Option(
        ...,
        "--model",
        "-m",
        help="Model name.",
    ),
    config: str = typer.Option(
        "agents/file_hypothesis.yaml",
        "--config",
        "-c",
        help="Agent config YAML (relative to config dir).",
    ),
    docker_image: str = typer.Option(
        "revelio/file-scan:latest",
        "--docker-image",
        help="Docker image to use.",
    ),
    max_workers: int = typer.Option(
        4,
        "--max-workers",
        "-w",
        help="Maximum number of parallel workers.",
    ),
    limit: Optional[int] = typer.Option(
        None,
        "--limit",
        "-l",
        help="Only run this many CVEs (useful for testing).",
    ),
    batch_id: Optional[str] = typer.Option(
        None,
        "--batch-id",
        "-b",
        help="Batch identifier. Saves output to output/<batch_id>/.",
    ),
    output_dir: Path = typer.Option(
        None,
        "--output-dir",
        "-o",
        help="Base output directory (overridden by --batch-id).",
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
    """Batch-run file-scan on single-file CVEs with downloaded repos."""
    if batch_id is not None:
        output_dir = Path("output") / batch_id
    elif output_dir is None:
        output_dir = Path("output/batch_file_scan")

    candidates = load_candidates(dataset, repos_dir)

    if not candidates:
        console.print("[bold red]No matching CVEs found.[/bold red]")
        raise typer.Exit(1)

    if limit is not None:
        candidates = candidates[:limit]

    # Skip CVEs that already have output
    skipped = []
    remaining = []
    for c in candidates:
        trajectory = output_dir / c["cve_id"] / "trajectory.json"
        if trajectory.exists():
            skipped.append(c)
        else:
            remaining.append(c)

    console.print(f"[bold green]Matched CVEs:[/bold green] {len(candidates)}")
    if skipped:
        console.print(f"[bold yellow]Skipped (already done):[/bold yellow] {len(skipped)}")
    candidates = remaining
    console.print(f"[bold green]Model:[/bold green] {model}")
    console.print(f"[bold green]Config:[/bold green] {config}")
    console.print(f"[bold green]Workers:[/bold green] {max_workers}")
    console.print()

    if dry_run:
        for c in candidates:
            console.print(f"  {c['cve_id']}: {c['target_file']}")
        console.print(f"\n[cyan]Total: {len(candidates)} (dry run, nothing executed)[/cyan]")
        return

    log_dir = output_dir / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    output_dir.mkdir(parents=True, exist_ok=True)

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
                config,
                docker_image,
                output_dir,
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
    console.print(f"  Output:     {output_dir}")
    console.print(f"  Logs:       {log_dir}")


if __name__ == "__main__":
    app()
