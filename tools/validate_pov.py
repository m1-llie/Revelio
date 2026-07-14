#!/usr/bin/env python3
"""Validate a PoV against both ARVO vul and fix versions (multi-agent runs).

This script works with multi-agent outputs where PoVs are named per hypothesis
and run metadata is stored in manifest.json.

Usage:
    # Single run, auto-discover all PoVs:
    python -m revelio.run.validate_if_target_multiAgent validate --run-dir output/arvo-1065-vul-clean_...

    # Single run, specific PoV:
    python -m revelio.run.validate_if_target_multiAgent validate --run-dir output/arvo-1065-vul-clean_... --pov output/.../pov_H03

    # Batch: validate all runs under an output directory:
    python -m revelio.run.validate_if_target_multiAgent batch --output-dir output/
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from revelio.environments.docker import DockerEnvironment
from revelio.run.crash_signals import (
    CRASH_SIGNATURES as CRASH_MARKERS,
    CRASH_SIGNAL_RETURN_CODES as CRASH_RETURN_CODES,
    check_crash as is_crash_detected,
)

console = Console()
app = typer.Typer(rich_markup_mode="rich")


def _summarize_output(output: str, limit: int = 2000) -> str:
    if output is None:
        return ""
    if len(output) <= limit:
        return output
    head = output[:1000]
    tail = output[-1000:]
    return f"{head}\n...\n{tail}"


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


def run_pov_in_container(image: str, pov_path: Path, timeout: int = 60) -> dict:
    env = None
    try:
        env = DockerEnvironment(
            image=image,
            cwd="/src",
            timeout=timeout,
            container_timeout="5m",
        )
        env.copy_to(pov_path, "/tmp/poc")
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


def _find_povs(run_dir: Path) -> list[Path]:
    """Find PoV deliverables in a run directory.

    Only looks in artifacts/deliverables/ for files named pov_* (not
    pov_recipe_*.json which live in artifacts/handoffs/).
    """
    deliverables = run_dir / "artifacts" / "deliverables"
    if deliverables.is_dir():
        # "pov_*" is current; "poc_*" is the legacy deliverable naming.
        candidates = sorted(
            p for p in list(deliverables.glob("pov_*")) + list(deliverables.glob("poc_*"))
            if p.is_file()
        )
    else:
        # Fallback: search recursively but exclude recipe JSON files
        candidates = sorted(
            p for p in list(run_dir.rglob("pov_*")) + list(run_dir.rglob("poc_*"))
            if p.is_file() and "pov_recipe" not in p.name and "poc_recipe" not in p.name
        )
    return candidates


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


def _validate_single_pov(
    pov_path: Path,
    vul_image: str,
    fix_image: str,
    timeout: int,
) -> dict:
    """Validate one PoV against vul and fix images. Returns a result dict."""
    pov_name = pov_path.name

    console.print(f"\n[bold cyan]--- Validating: {pov_name} ---[/bold cyan]")
    console.print(f"[dim]  PoV path: {pov_path}[/dim]")

    # Test on vulnerable version
    console.print(f"  Testing on [bold]{vul_image}[/bold] (vul) ...")
    vul_result = run_pov_in_container(vul_image, pov_path, timeout)
    if not vul_result.get("success"):
        console.print(f"  [bold red]Error on vul version:[/bold red] {vul_result.get('error')}")
        return {
            "pov": pov_name,
            "pov_path": str(pov_path),
            "status": "error",
            "error": f"vul: {vul_result.get('error')}",
            "vul_crash": False,
            "fix_crash": False,
            "validation_passed": False,
        }

    vul_crashed = vul_result.get("crash_detected", False)
    if vul_crashed:
        console.print("  [green]Crash detected on vulnerable version[/green]")
    else:
        console.print("  [yellow]No crash on vulnerable version[/yellow]")

    # Test on fixed version
    console.print(f"  Testing on [bold]{fix_image}[/bold] (fix) ...")
    fix_result = run_pov_in_container(fix_image, pov_path, timeout)
    if not fix_result.get("success"):
        console.print(f"  [bold red]Error on fix version:[/bold red] {fix_result.get('error')}")
        return {
            "pov": pov_name,
            "pov_path": str(pov_path),
            "status": "error",
            "error": f"fix: {fix_result.get('error')}",
            "vul_crash": vul_crashed,
            "fix_crash": False,
            "validation_passed": False,
        }

    fix_crashed = fix_result.get("crash_detected", False)

    # Determine outcome
    passed = vul_crashed and not fix_crashed
    if passed:
        status = "TARGETED"
        console.print(f"  [bold green]TARGETED[/bold green] - crashes vul, not fix")
    elif fix_crashed:
        status = "UNTARGETED"
        console.print(f"  [bold red]UNTARGETED[/bold red] - PoV still crashes fix version")
    elif not vul_crashed:
        status = "NOCRASH"
        console.print(f"  [bold yellow]NOCRASH[/bold yellow] - no crash on vul version")
    else:
        status = "UNTARGETED"

    result = {
        "pov": pov_name,
        "pov_path": str(pov_path),
        "status": status,
        "vul_crash": vul_crashed,
        "fix_crash": fix_crashed,
        "validation_passed": passed,
        "vul_image": vul_image,
        "fix_image": fix_image,
        "vul_returncode": vul_result.get("returncode"),
        "fix_returncode": fix_result.get("returncode"),
        "vul_output_excerpt": _summarize_output(vul_result.get("output", "")),
        "fix_output_excerpt": _summarize_output(fix_result.get("output", "")),
    }

    # Save per-PoV validation result
    result_path = pov_path.parent / f"validation_{pov_name}.json"
    result_path.write_text(json.dumps(result, indent=2))
    console.print(f"  [dim]Saved: {result_path}[/dim]")

    return result


@app.command()
def validate(
    run_dir: Path = typer.Option(
        ...,
        "--run-dir",
        "-r",
        help="Output directory from detect.py (multi-agent run).",
    ),
    pov: Path | None = typer.Option(
        None,
        "--pov",
        help="Path to a specific PoV file. If omitted, validates all PoVs found.",
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
    """Validate PoV(s) for a single run directory."""
    run_dir = run_dir.resolve()
    if not run_dir.exists():
        console.print(f"[bold red]Run directory does not exist:[/bold red] {run_dir}")
        raise typer.Exit(1)

    # Resolve images
    try:
        vul_image = _resolve_arvo_image(run_dir, arvo_image)
    except ValueError as exc:
        console.print(f"[bold red]{exc}[/bold red]")
        raise typer.Exit(1)
    fix_image = get_fix_image(vul_image)

    # Ensure images exist
    console.print(f"[bold cyan]Vulnerable image:[/bold cyan] {vul_image}")
    console.print(f"[bold cyan]Fixed image:[/bold cyan] {fix_image}")
    console.print("[bold]Checking Docker images...[/bold]")
    if not ensure_image_exists(vul_image, pull_timeout):
        console.print(f"[bold red]Cannot access vulnerable image: {vul_image}[/bold red]")
        raise typer.Exit(1)
    if not ensure_image_exists(fix_image, pull_timeout):
        console.print(f"[bold red]Cannot access fixed image: {fix_image}[/bold red]")
        raise typer.Exit(1)

    # Find PoVs
    if pov:
        pov_paths = [pov.resolve()]
        if not pov_paths[0].exists():
            console.print(f"[bold red]PoV file not found:[/bold red] {pov_paths[0]}")
            raise typer.Exit(1)
    else:
        pov_paths = _find_povs(run_dir)
        if not pov_paths:
            console.print("[bold yellow]No PoV files found in this run.[/bold yellow]")
            raise typer.Exit(0)
        console.print(f"[bold]Found {len(pov_paths)} PoV(s) to validate.[/bold]")

    # Validate each PoV
    results = []
    for pov_path in pov_paths:
        r = _validate_single_pov(pov_path, vul_image, fix_image, timeout)
        results.append(r)

    # Summary
    console.print()
    console.print("[bold]═══════════════════════════════════════[/bold]")
    passed = sum(1 for r in results if r["validation_passed"])
    failed = sum(1 for r in results if r["status"] == "UNTARGETED")
    inconclusive = sum(1 for r in results if r["status"] == "NOCRASH")
    errors = sum(1 for r in results if r["status"] == "error")
    console.print(
        f"[bold]{len(results)} PoV(s):[/bold] "
        f"[green]{passed} passed[/green], "
        f"[red]{failed} failed[/red], "
        f"[yellow]{inconclusive} inconclusive[/yellow], "
        f"[red]{errors} error(s)[/red]"
    )
    console.print("[bold]═══════════════════════════════════════[/bold]")

    # Save combined results
    combined_path = run_dir / "validation_summary.json"
    combined_path.write_text(json.dumps(results, indent=2))
    console.print(f"\n[dim]Summary saved to:[/dim] {combined_path}")


@app.command()
def batch(
    output_dir: Path = typer.Option(
        "output",
        "--output-dir",
        "-o",
        help="Parent directory containing run folders.",
    ),
    run_glob: str = typer.Option(
        "arvo-*",
        "--run-glob",
        help="Glob pattern for run directories under output-dir.",
    ),
    timeout: int = typer.Option(
        60,
        "--timeout",
        "-t",
        help="Timeout in seconds for each PoV test run.",
    ),
    pull_timeout: int = typer.Option(
        300,
        "--pull-timeout",
        help="Timeout in seconds for pulling Docker images.",
    ),
) -> None:
    """Batch-validate all runs under an output directory.

    Scans for run directories, finds PoV deliverables in each, validates them,
    and prints a summary table.
    """
    output_dir = output_dir.resolve()
    if not output_dir.exists():
        console.print(f"[bold red]Output directory does not exist:[/bold red] {output_dir}")
        raise typer.Exit(1)

    run_dirs = sorted(
        d for d in output_dir.glob(run_glob) if d.is_dir() and (d / "manifest.json").exists()
    )

    if not run_dirs:
        console.print(f"[bold yellow]No run directories matching '{run_glob}' found in {output_dir}[/bold yellow]")
        raise typer.Exit(0)

    console.print(f"[bold]Found {len(run_dirs)} run(s) to scan.[/bold]\n")

    # Collect results across all runs
    all_results: list[dict] = []

    # Cache images we've already verified
    verified_images: set[str] = set()

    for run_dir in run_dirs:
        run_name = run_dir.name
        povs = _find_povs(run_dir)

        if not povs:
            all_results.append({
                "run": run_name,
                "pov": "-",
                "status": "NO_POV",
                "vul_crash": False,
                "fix_crash": False,
                "validation_passed": False,
            })
            continue

        # Resolve images
        try:
            vul_image = _resolve_arvo_image(run_dir, None)
        except ValueError:
            console.print(f"[red]Cannot resolve image for {run_name}, skipping.[/red]")
            all_results.append({
                "run": run_name,
                "pov": "-",
                "status": "IMG_ERROR",
                "vul_crash": False,
                "fix_crash": False,
                "validation_passed": False,
            })
            continue

        fix_image = get_fix_image(vul_image)

        # Ensure images exist (only check once per image pair)
        if vul_image not in verified_images:
            if not ensure_image_exists(vul_image, pull_timeout):
                console.print(f"[red]Cannot access {vul_image}, skipping {run_name}.[/red]")
                continue
            verified_images.add(vul_image)
        if fix_image not in verified_images:
            if not ensure_image_exists(fix_image, pull_timeout):
                console.print(f"[red]Cannot access {fix_image}, skipping {run_name}.[/red]")
                continue
            verified_images.add(fix_image)

        # Validate each PoV
        for pov_path in povs:
            r = _validate_single_pov(pov_path, vul_image, fix_image, timeout)
            r["run"] = run_name
            all_results.append(r)

    # Print summary table
    console.print("\n")
    table = Table(title="Batch Validation Summary", show_lines=True)
    table.add_column("Run", style="cyan", max_width=60)
    table.add_column("PoV", style="white")
    table.add_column("Vul Crash", justify="center")
    table.add_column("Fix Crash", justify="center")
    table.add_column("Result", justify="center")

    for r in all_results:
        run_short = r.get("run", "?")
        pov_name = r.get("pov", "-")
        status = r.get("status", "?")

        if status == "NO_POV":
            table.add_row(run_short, "[dim]no PoV[/dim]", "-", "-", "[dim]NO POV[/dim]")
        elif status == "TARGETED":
            table.add_row(run_short, pov_name, "[green]YES[/green]", "[green]no[/green]", "[bold green]TARGETED[/bold green]")
        elif status == "UNTARGETED":
            vul_str = "[green]YES[/green]" if r.get("vul_crash") else "[yellow]no[/yellow]"
            table.add_row(run_short, pov_name, vul_str, "[red]YES[/red]", "[bold red]UNTARGETED[/bold red]")
        elif status == "NOCRASH":
            table.add_row(run_short, pov_name, "[yellow]no[/yellow]", "[yellow]no[/yellow]", "[bold yellow]NOCRASH[/bold yellow]")
        elif status == "error":
            table.add_row(run_short, pov_name, "-", "-", f"[red]ERROR: {r.get('error', '?')[:40]}[/red]")
        else:
            table.add_row(run_short, pov_name, "-", "-", f"[dim]{status}[/dim]")

    console.print(table)

    # Print counters
    total_povs = sum(1 for r in all_results if r.get("status") != "NO_POV")
    passed = sum(1 for r in all_results if r.get("validation_passed"))
    failed = sum(1 for r in all_results if r.get("status") == "UNTARGETED")
    inconclusive = sum(1 for r in all_results if r.get("status") == "NOCRASH")
    no_pov = sum(1 for r in all_results if r.get("status") == "NO_POV")
    console.print(
        f"\n[bold]{len(run_dirs)} run(s), {total_povs} PoV(s) tested:[/bold] "
        f"[green]{passed} passed[/green], "
        f"[red]{failed} failed[/red], "
        f"[yellow]{inconclusive} inconclusive[/yellow], "
        f"[dim]{no_pov} runs had no PoV[/dim]"
    )

    # Save batch results
    batch_result_path = output_dir / "batch_validation.json"
    batch_result_path.write_text(json.dumps(all_results, indent=2))
    console.print(f"[dim]Batch results saved to:[/dim] {batch_result_path}")


if __name__ == "__main__":
    app()
