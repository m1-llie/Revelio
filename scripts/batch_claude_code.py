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
import os
import re
import signal
import subprocess
import sys
import uuid
from concurrent.futures import ProcessPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import typer
import yaml
from rich.console import Console

console = Console()
app = typer.Typer(rich_markup_mode="rich", pretty_exceptions_show_locals=False)

SCRIPTS_DIR = Path("/srv/share/vulagent/")
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
You have access to a Docker container (ID: {container_id}) that contains a \
software repository at /src.

Your task: analyze the file `/src/{target_file}` for security vulnerabilities.

To run commands inside the container, use:
  docker exec {container_id} bash -c 'your_command'

## Recommended Workflow

This workflow should be done step-by-step so that you can iterate on your analysis.

1. Identifying potential vulnerability sinks in the file
2. Form hypotheses about how there might be a source that violates the safe precondition for the sink
3. Inspect more functions and files to validate that the hypothesis is correct
4. Submit the hypotheses in the EXACT JSON format described below

## Output (CRITICAL — you MUST follow this format exactly)

When you are done with your analysis, your FINAL message must contain EXACTLY ONE \
JSON code block with your structured results. The JSON must be an array of hypothesis \
objects with this schema:

```json
[
  {{
    "hypothesis": {{
      "summary": "Brief description of the vulnerability",
      "files_reviewed": ["path/to/file1.c", "path/to/file2.h"],
      "harness_entry": "function_name or null",
      "call_chains": ["caller -> middle -> vulnerable_function"],
      "hotspots": [
        {{
          "file_path": "path/to/file.c",
          "line_start": 100,
          "line_end": 110,
          "function": "vulnerable_function",
          "context": "Brief description of why this location is vulnerable"
        }}
      ],
      "warnings": ["Description of the security impact"]
    }}
  }}
]
```

**IMPORTANT rules for the JSON output:**
- `hotspots` is the most important field — every hypothesis MUST have at least one hotspot
- `file_path` must be relative to `/src/` (e.g., `src/parser.c` not `/src/src/parser.c`)
- `line_start` and `line_end` must be integers pointing to the exact vulnerable lines
- `function` must be the name of the function containing the vulnerability
- If no vulnerabilities are found, output an empty array: `[]`

Focus on real, exploitable issues — not style or best-practice suggestions.\
"""


def extract_payload_from_result(result_text: str) -> list[dict] | None:
    """Extract the structured JSON payload from Claude Code's result text.

    Looks for a JSON array in a code block or standalone in the text.
    Returns the parsed list of hypothesis dicts, or None if not found.
    """
    if not result_text:
        return None

    # Try: ```json ... ``` code block
    for m in re.finditer(r'```(?:json)?\s*\n(.*?)```', result_text, re.DOTALL):
        try:
            parsed = json.loads(m.group(1))
            if isinstance(parsed, list):
                return parsed
        except (json.JSONDecodeError, ValueError):
            continue

    # Try: standalone JSON array in the text
    for m in re.finditer(r'(\[\s*\{.*?\}\s*\])', result_text, re.DOTALL):
        try:
            parsed = json.loads(m.group(1))
            if isinstance(parsed, list):
                return parsed
        except (json.JSONDecodeError, ValueError):
            continue

    return None


def build_submission(result_text: str, payload: list[dict] | None) -> str:
    """Build a YAML submission string matching the file_scan finish-tool format."""
    status = "success" if payload else "failure"
    analysis = ""
    if result_text:
        # Use first ~500 chars of the result as analysis summary
        analysis = result_text[:500].split("\n\n")[0].strip()

    data = {
        "status": status,
        "analysis": analysis,
        "result_script": "none",
        "poc": "none",
        "report": "none",
    }
    if payload is not None:
        data["payload"] = json.dumps(payload)
    return yaml.dump(data, sort_keys=False)


def build_trajectory_json(
    result_event: dict | None,
    raw_events: list[dict],
    submission: str,
    cve_id: str,
    target_file: str,
    docker_image: str,
    model: str,
    started_at: datetime,
    finished_at: datetime,
    run_dir: str,
) -> dict:
    """Build a trajectory.json matching the file_scan agent output structure."""
    # Collect model usage stats from the result event
    model_stats = {}
    if result_event:
        cost = result_event.get("total_cost_usd", 0)
        turns = result_event.get("num_turns", 0)
        model_stats = {
            "instance_cost": cost,
            "api_calls": turns,
        }

    # Convert raw stream events to a simplified messages list
    messages = []
    for event in raw_events:
        etype = event.get("type")
        if etype == "assistant":
            messages.append({
                "role": "assistant",
                "content": event.get("message", {}).get("content", ""),
            })
        elif etype == "user":
            messages.append({
                "role": "user",
                "content": event.get("message", {}).get("content", ""),
            })

    info = {
        "exit_status": "Submitted" if submission else "Failed",
        "submission": submission,
        "model_stats": model_stats,
        "mini_version": "0.0.1",
        "config": {
            "agent": {
                "type": "claude_code",
                "model": model,
            },
        },
        "folder_path": None,
        "target_file": target_file,
        "docker_image": docker_image,
        "started_at_utc": started_at.isoformat(),
        "finished_at_utc": finished_at.isoformat(),
        "duration_seconds": (finished_at - started_at).total_seconds(),
        "run_dir": run_dir,
    }

    return {
        "info": info,
        "messages": messages,
        "trajectory_format": "vul-agent-1",
    }


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
    cve_dir = output_dir / cve_id
    cve_dir.mkdir(parents=True, exist_ok=True)

    container_id = None
    started_at = datetime.now(timezone.utc)
    try:
        container_id = start_container(repo_path, docker_image)
        prompt = PROMPT_TEMPLATE.format(container_id=container_id, target_file=target_file)

        cmd = [
            "claude",
            "-p", prompt,
            "--model", model,
            "--output-format", "stream-json",
            "--verbose",
            "--max-turns", str(max_turns),
            "--allowedTools", f"Bash(docker exec {container_id}:*)",
        ]
        if max_budget > 0:
            cmd.extend(["--max-budget-usd", str(max_budget)])

        raw_trajectory_path = cve_dir / "trajectory.jsonl"

        with open(log_path, "w") as log_file, open(raw_trajectory_path, "w") as traj_file:
            result = subprocess.run(
                cmd,
                stdout=traj_file,
                stderr=log_file,
                timeout=3600,
            )

        finished_at = datetime.now(timezone.utc)

        # Parse all events from the stream-json output
        raw_events = []
        result_event = None
        with open(raw_trajectory_path) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    event = json.loads(line)
                    raw_events.append(event)
                    if event.get("type") == "result":
                        result_event = event
                except json.JSONDecodeError:
                    pass

        # Extract the final result text
        result_text = result_event.get("result", "") if result_event else ""

        # Extract structured payload from the result
        payload = extract_payload_from_result(result_text)

        # Build submission in file_scan format
        submission = build_submission(result_text, payload)

        # Save report.json (legacy format for backwards compat)
        report_path = cve_dir / "report.json"
        if result_event:
            report_path.write_text(json.dumps(result_event, indent=2))

        # Save trajectory.json in the file_scan agent format
        trajectory = build_trajectory_json(
            result_event=result_event,
            raw_events=raw_events,
            submission=submission,
            cve_id=cve_id,
            target_file=target_file,
            docker_image=docker_image,
            model=model,
            started_at=started_at,
            finished_at=finished_at,
            run_dir=str(cve_dir),
        )
        trajectory_path = cve_dir / "trajectory.json"
        trajectory_path.write_text(json.dumps(trajectory, indent=2))

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
        help="Total number of CVEs to process (including already-completed ones).",
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

    # Apply limit to total candidates (including ones already done), then skip existing
    before = len(candidates)
    if limit is not None:
        candidates = candidates[:limit]

    def _is_done(cve_id: str) -> bool:
        """Check if a CVE run is complete: report.json exists and is_error is not true."""
        report_path = resolved_output_dir / cve_id / "report.json"
        if not report_path.exists():
            return False
        try:
            with open(report_path) as f:
                report = json.load(f)
            return not report.get("is_error", False)
        except (json.JSONDecodeError, OSError):
            return False

    already_done = [c for c in candidates if _is_done(c["cve_id"])]
    skipped = len(already_done)
    candidates = [c for c in candidates if not _is_done(c["cve_id"])]

    # Find incomplete runs: directory exists but not successfully done
    incomplete = [c for c in candidates if (resolved_output_dir / c["cve_id"]).exists()]
    if incomplete and not dry_run:
        console.print(f"[bold yellow]Found {len(incomplete)} incomplete/errored run(s):[/bold yellow]")
        for c in incomplete:
            console.print(f"  {c['cve_id']}: {resolved_output_dir / c['cve_id']}")
        import shutil
        answer = input("Remove these directories and re-run them? [y/N]: ").strip().lower()
        if answer in ("y", "yes"):
            for c in incomplete:
                shutil.rmtree(resolved_output_dir / c["cve_id"])
                console.print(f"  [dim]Removed {c['cve_id']}[/dim]")
            console.print()
        else:
            # Keep them but skip them
            incomplete_ids = {c["cve_id"] for c in incomplete}
            candidates = [c for c in candidates if c["cve_id"] not in incomplete_ids]
            skipped += len(incomplete_ids)
            console.print(f"[dim]Skipping incomplete runs.[/dim]\n")

    console.print(f"[bold green]Batch ID:[/bold green] {batch_id}")
    console.print(f"[bold green]Output dir:[/bold green] {resolved_output_dir}")
    console.print(f"[bold green]Matched CVEs:[/bold green] {before}")
    if skipped:
        console.print(f"[bold yellow]Skipped (already done):[/bold yellow] {skipped}")
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

    executor = ProcessPoolExecutor(max_workers=max_workers)
    try:
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

    except KeyboardInterrupt:
        console.print("\n[bold red]Interrupted! Cancelling pending tasks and killing workers...[/bold red]")
        for future in future_to_cve:
            future.cancel()
        executor.shutdown(wait=False, cancel_futures=True)
        # Kill child processes in our process group
        os.killpg(0, signal.SIGTERM)
        sys.exit(1)
    finally:
        executor.shutdown(wait=True)

    console.print(f"\n[bold green]Batch complete.[/bold green]")
    console.print(f"  Total:      {total}")
    console.print(f"  Successful: {successful}")
    console.print(f"  Failed:     {failed}")
    console.print(f"  Output:     {resolved_output_dir}")
    console.print(f"  Logs:       {log_dir}")


if __name__ == "__main__":
    app()
