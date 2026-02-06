#!/usr/bin/env python3
"""Validate a PoC against both ARVO vul and fix versions (multi-agent runs).

This script works with multi-agent outputs where PoCs are named per hypothesis
and run metadata is stored in manifest.json.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import typer
from rich.console import Console

from vulagent.environments.docker import DockerEnvironment

console = Console()
app = typer.Typer(rich_markup_mode="rich")

# Markers indicating a crash in sanitizer output
CRASH_MARKERS = [
    "AddressSanitizer", "SEGV", "heap-buffer-overflow",
    "stack-buffer-overflow", "use-after-free", "ABORTING",
    "LeakSanitizer", "MemorySanitizer", "UndefinedBehaviorSanitizer",
    "SUMMARY: ", "==ERROR:", "DEADLYSIGNAL",
]

# Return codes that indicate a crash
CRASH_RETURN_CODES = {1, 134, 136, 139}  # ASAN, SIGABRT, SIGFPE, SIGSEGV


def _summarize_output(output: str, limit: int = 2000) -> str:
    if output is None:
        return ""
    if len(output) <= limit:
        return output
    head = output[:1000]
    tail = output[-1000:]
    return f"{head}\n...\n{tail}"


def is_crash_detected(output: str, returncode: int | None) -> bool:
    has_crash_marker = any(marker in output for marker in CRASH_MARKERS)
    has_crash_returncode = False
    if returncode is not None:
        if returncode >= 128:
            has_crash_returncode = True
        elif returncode in CRASH_RETURN_CODES:
            has_crash_returncode = True
    return has_crash_marker or has_crash_returncode


def get_fix_image(vul_image: str) -> str:
    base_image = vul_image.replace("-clean", "")
    if "-vul" in base_image:
        return base_image.replace("-vul", "-fix")
    raise ValueError(f"Cannot determine fix image from: {vul_image}")


def ensure_image_exists(image: str, pull_timeout: int = 300) -> bool:
    check_cmd = ["docker", "image", "inspect", image]
    result = subprocess.run(check_cmd, capture_output=True, text=True)
    if result.returncode == 0:
        console.print(f"[dim]Image {image} found locally[/dim]")
        return True
    console.print(f"[yellow]Image {image} not found locally, pulling...[/yellow]")
    pull_cmd = ["docker", "pull", image]
    try:
        result = subprocess.run(pull_cmd, capture_output=True, text=True, timeout=pull_timeout)
        if result.returncode == 0:
            console.print(f"[green]Successfully pulled {image}[/green]")
            return True
        console.print(f"[red]Failed to pull {image}: {result.stderr}[/red]")
        return False
    except subprocess.TimeoutExpired:
        console.print(f"[red]Timeout pulling {image}[/red]")
        return False


def run_poc_in_container(image: str, poc_path: Path, timeout: int = 60) -> dict:
    env = None
    try:
        env = DockerEnvironment(
            image=image,
            cwd="/src",
            timeout=timeout,
            container_timeout="5m",
        )
        env.copy_to(poc_path, "/tmp/poc")
        result = env.execute("arvo 2>&1", timeout=timeout)
        output = result.get("output", "")
        returncode = result.get("returncode")
        crash_detected = is_crash_detected(output, returncode)
        return {
            "success": True,
            "returncode": returncode,
            "output": output,
            "crash_detected": crash_detected,
        }
    except subprocess.TimeoutExpired:
        return {"success": False, "error": "Command timed out", "crash_detected": False}
    except Exception as e:
        return {"success": False, "error": str(e), "crash_detected": False}
    finally:
        if env:
            env.cleanup()


def _find_poc(run_dir: Path) -> Path:
    candidates = list(run_dir.rglob("poc_*"))
    candidates = [p for p in candidates if p.is_file()]
    if len(candidates) == 1:
        return candidates[0]
    if not candidates:
        raise ValueError("No PoC files found under run directory.")
    raise ValueError(
        "Multiple PoC files found; please specify --poc explicitly:\n"
        + "\n".join(str(p) for p in candidates)
    )


def _resolve_arvo_image(run_dir: Path, override: str | None) -> str:
    if override:
        return override
    manifest = run_dir / "manifest.json"
    if manifest.exists():
        data = json.loads(manifest.read_text())
        if data.get("target_type") == "arvo" and data.get("target_ref"):
            return data["target_ref"]
    traj = run_dir / "trajectory.json"
    if traj.exists():
        data = json.loads(traj.read_text())
        info = data.get("info", {})
        if info.get("arvo_image"):
            return info["arvo_image"]
    raise ValueError("Could not determine ARVO image. Use --arvo-image.")


@app.command()
def main(
    run_dir: Path = typer.Option(
        ...,
        "--run-dir",
        "-r",
        help="Output directory from detect.py (multi-agent run).",
    ),
    poc: Path | None = typer.Option(
        None,
        "--poc",
        help="Path to PoC file (e.g., hypothesis_H01/poc_H01).",
    ),
    arvo_image: str | None = typer.Option(
        None,
        "--arvo-image",
        help="Explicit ARVO vul image tag (overrides manifest.json).",
    ),
    timeout: int = typer.Option(
        60,
        "--timeout",
        "-t",
        help="Timeout in seconds for each test run.",
    ),
    pull_timeout: int = typer.Option(
        300,
        "--pull-timeout",
        help="Timeout in seconds for pulling Docker images.",
    ),
) -> None:
    run_dir = run_dir.resolve()
    if not run_dir.exists():
        console.print(f"[bold red]Run directory does not exist:[/bold red] {run_dir}")
        raise typer.Exit(1)

    poc_path = poc.resolve() if poc else _find_poc(run_dir)
    if not poc_path.exists():
        console.print(f"[bold red]PoC file not found:[/bold red] {poc_path}")
        raise typer.Exit(1)

    try:
        vul_image = _resolve_arvo_image(run_dir, arvo_image)
    except ValueError as exc:
        console.print(f"[bold red]{exc}[/bold red]")
        raise typer.Exit(1)

    fix_image = get_fix_image(vul_image)

    console.print(f"[bold cyan]Validating PoC:[/bold cyan] {poc_path}")
    console.print(f"[bold cyan]Vulnerable image:[/bold cyan] {vul_image}")
    console.print(f"[bold cyan]Fixed image:[/bold cyan] {fix_image}")
    console.print()

    console.print("[bold]Checking Docker images...[/bold]")
    if not ensure_image_exists(vul_image, pull_timeout):
        console.print(f"[bold red]Cannot access vulnerable image: {vul_image}[/bold red]")
        raise typer.Exit(1)
    if not ensure_image_exists(fix_image, pull_timeout):
        console.print(f"[bold red]Cannot access fixed image: {fix_image}[/bold red]")
        raise typer.Exit(1)

    console.print()
    console.print("[bold]Testing on vulnerable version...[/bold]")
    vul_result = run_poc_in_container(vul_image, poc_path, timeout)
    if not vul_result.get("success"):
        console.print(f"[bold red]Failed to test on vul version:[/bold red] {vul_result.get('error')}")
        raise typer.Exit(1)
    if vul_result.get("crash_detected"):
        console.print("[bold green]✓ Crash detected on vulnerable version[/bold green]")
    else:
        console.print("[bold yellow]⚠ No crash on vulnerable version[/bold yellow]")

    console.print()
    console.print("[bold]Testing on fixed version...[/bold]")
    fix_result = run_poc_in_container(fix_image, poc_path, timeout)
    if not fix_result.get("success"):
        console.print(f"[bold red]Failed to test on fix version:[/bold red] {fix_result.get('error')}")
        raise typer.Exit(1)

    console.print()
    console.print("[bold]═══════════════════════════════════════[/bold]")

    vul_crashed = vul_result.get("crash_detected", False)
    fix_crashed = fix_result.get("crash_detected", False)
    if fix_crashed:
        console.print("[bold red]✗ VALIDATION FAILED[/bold red]")
        console.print("[red]PoC still crashes the fixed version[/red]")
        console.print("[dim]Fix version output preview:[/dim]")
        console.print(fix_result.get("output", "")[:1000])
    elif not vul_crashed:
        console.print("[bold yellow]⚠ VALIDATION INCONCLUSIVE[/bold yellow]")
        console.print("[yellow]PoC did not crash vulnerable version[/yellow]")
    else:
        console.print("[bold green]✓ VALIDATION PASSED[/bold green]")
        console.print("[green]PoC crashes vul version but NOT fix version[/green]")

    console.print("[bold]═══════════════════════════════════════[/bold]")

    validation_result = {
        "vul_image": vul_image,
        "fix_image": fix_image,
        "poc_path": str(poc_path),
        "vul_crash": vul_crashed,
        "fix_crash": fix_crashed,
        "validation_passed": vul_crashed and not fix_crashed,
        "vul_returncode": vul_result.get("returncode"),
        "fix_returncode": fix_result.get("returncode"),
        "vul_output_excerpt": _summarize_output(vul_result.get("output", "")),
        "fix_output_excerpt": _summarize_output(fix_result.get("output", "")),
    }

    result_path = poc_path.parent / "validation.json"
    result_path.write_text(json.dumps(validation_result, indent=2))
    console.print(f"\n[dim]Validation result saved to:[/dim] {result_path}")

    if fix_crashed:
        raise typer.Exit(1)


if __name__ == "__main__":
    app()
