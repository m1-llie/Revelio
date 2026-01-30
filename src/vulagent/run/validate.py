#!/usr/bin/env python3
"""Validate a PoC against both ARVO vul and fix versions.

This script takes the output from detect.py and verifies that:
1. The PoC crashes the vulnerable version
2. The PoC does NOT crash the fixed version (confirms correct vulnerability)

Usage:
    python -m vulagent.run.validate --run-dir output/arvo-14935-vul_20260130-103945
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
# - Codes >= 128 indicate the process was killed by a signal (128 + signal_number)
# - SIGSEGV=11 -> 139, SIGABRT=6 -> 134, SIGFPE=8 -> 136
# - ASAN typically returns 1 on detection
CRASH_RETURN_CODES = {1, 134, 136, 139}  # ASAN, SIGABRT, SIGFPE, SIGSEGV


def is_crash_detected(output: str, returncode: int | None) -> bool:
    """Determine if a crash occurred based on output and return code.
    
    Uses multiple signals for robust detection:
    1. Sanitizer markers in output (most reliable)
    2. Return code indicating signal termination (>= 128)
    3. Known crash return codes (1 for ASAN)
    """
    # Check for sanitizer output markers
    has_crash_marker = any(marker in output for marker in CRASH_MARKERS)
    
    # Check return code
    has_crash_returncode = False
    if returncode is not None:
        # Signal termination (128 + signal)
        if returncode >= 128:
            has_crash_returncode = True
        # Known crash codes
        elif returncode in CRASH_RETURN_CODES:
            has_crash_returncode = True
    
    # Crash if either condition is met, but prioritize marker detection
    # (markers are more specific to sanitizer crashes)
    return has_crash_marker or has_crash_returncode


def get_fix_image(vul_image: str) -> str:
    """Convert a -vul image tag to -fix."""
    if "-vul" in vul_image:
        return vul_image.replace("-vul", "-fix")
    raise ValueError(f"Cannot determine fix image from: {vul_image}")


def ensure_image_exists(image: str, pull_timeout: int = 300) -> bool:
    """Check if image exists locally, pull if not. Returns True if available."""
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
    """Run a PoC file in a container using DockerEnvironment."""
    env = None
    try:
        # Start container with short timeout for validation
        env = DockerEnvironment(
            image=image,
            cwd="/src",
            timeout=timeout,
            container_timeout="5m",
        )
        
        # Copy PoC to /tmp/poc (where arvo expects it)
        env.copy_to(poc_path, "/tmp/poc")
        
        # Run arvo
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


@app.command()
def main(
    run_dir: Path = typer.Option(
        ...,
        "--run-dir",
        "-r",
        help="Output directory from detect.py run (contains trajectory.json and poc).",
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
    """Validate a PoC against both ARVO vul and fix versions."""
    
    run_dir = run_dir.resolve()
    if not run_dir.exists():
        console.print(f"[bold red]Run directory does not exist:[/bold red] {run_dir}")
        raise typer.Exit(1)
    
    # Load trajectory to get the ARVO image
    traj_path = run_dir / "trajectory.json"
    if not traj_path.exists():
        console.print(f"[bold red]trajectory.json not found in:[/bold red] {run_dir}")
        raise typer.Exit(1)
    
    traj = json.loads(traj_path.read_text())
    info = traj.get("info", {})
    
    vul_image = info.get("arvo_image")
    if not vul_image:
        console.print("[bold red]Not an ARVO run (no arvo_image in trajectory).[/bold red]")
        raise typer.Exit(1)
    
    task_status = info.get("task_status")
    if task_status != "success":
        console.print(f"[bold yellow]Detection was not successful (status={task_status}).[/bold yellow]")
        console.print("Validation requires a successful detection with PoC.")
        raise typer.Exit(1)
    
    # Check for PoC file
    poc_path = run_dir / "poc"
    if not poc_path.exists():
        console.print(f"[bold red]PoC file not found:[/bold red] {poc_path}")
        raise typer.Exit(1)
    
    fix_image = get_fix_image(vul_image)
    
    console.print(f"[bold cyan]Validating PoC from:[/bold cyan] {run_dir}")
    console.print(f"[bold cyan]Vulnerable image:[/bold cyan] {vul_image}")
    console.print(f"[bold cyan]Fixed image:[/bold cyan] {fix_image}")
    console.print(f"[bold cyan]PoC file:[/bold cyan] {poc_path} ({poc_path.stat().st_size} bytes)")
    console.print()
    
    # Ensure both images exist (pull if needed)
    console.print("[bold]Checking Docker images...[/bold]")
    if not ensure_image_exists(vul_image, pull_timeout):
        console.print(f"[bold red]Cannot access vulnerable image: {vul_image}[/bold red]")
        raise typer.Exit(1)
    
    if not ensure_image_exists(fix_image, pull_timeout):
        console.print(f"[bold red]Cannot access fixed image: {fix_image}[/bold red]")
        raise typer.Exit(1)
    
    console.print()
    
    # Test on vulnerable version
    console.print("[bold]Testing on vulnerable version...[/bold]")
    vul_result = run_poc_in_container(vul_image, poc_path, timeout)
    
    if not vul_result.get("success"):
        console.print(f"[bold red]Failed to test on vul version:[/bold red] {vul_result.get('error')}")
        raise typer.Exit(1)
    
    if vul_result.get("crash_detected"):
        console.print("[bold green]✓ Crash detected on vulnerable version[/bold green]")
    else:
        console.print("[bold yellow]⚠ No crash on vulnerable version - PoC may be invalid[/bold yellow]")
        console.print("[dim]Output preview:[/dim]")
        console.print(vul_result.get("output", "")[:500])
    
    console.print()
    
    # Test on fixed version
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
        console.print("[red]PoC still crashes the fixed version - may be wrong vulnerability[/red]")
        console.print("[dim]Fix version output preview:[/dim]")
        console.print(fix_result.get("output", "")[:1000])
    elif not vul_crashed:
        console.print("[bold yellow]⚠ VALIDATION INCONCLUSIVE[/bold yellow]")
        console.print("[yellow]PoC did not crash vulnerable version[/yellow]")
    else:
        console.print("[bold green]✓ VALIDATION PASSED[/bold green]")
        console.print("[green]PoC crashes vul version but NOT fix version - correct vulnerability confirmed![/green]")
    
    console.print("[bold]═══════════════════════════════════════[/bold]")
    
    # Save validation result
    validation_result = {
        "vul_image": vul_image,
        "fix_image": fix_image,
        "poc_path": str(poc_path),
        "vul_crash": vul_crashed,
        "fix_crash": fix_crashed,
        "validation_passed": vul_crashed and not fix_crashed,
    }
    
    result_path = run_dir / "validation.json"
    result_path.write_text(json.dumps(validation_result, indent=2))
    console.print(f"\n[dim]Validation result saved to:[/dim] {result_path}")
    
    if fix_crashed:
        raise typer.Exit(1)


if __name__ == "__main__":
    app()
