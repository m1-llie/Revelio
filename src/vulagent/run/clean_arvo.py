#!/usr/bin/env python3
"""Clean ARVO Docker images for zero-day vulnerability detection.

Removes pre-existing PoCs, crashers, seed corpus, and VCS metadata from ARVO images
so the agent must find vulnerabilities from scratch.

This creates a new Docker image tagged with '-clean' suffix.

Usage:
    # Clean a specific image
    python -m vulagent.run.clean_arvo --image n132/arvo:14935-vul
    
    # Clean and save as new tag
    python -m vulagent.run.clean_arvo --image n132/arvo:14935-vul --output-tag my-repo/arvo:14935-clean
    
    # Just inspect what would be removed (dry run)
    python -m vulagent.run.clean_arvo --image n132/arvo:14935-vul --dry-run
"""

from __future__ import annotations

import subprocess
import uuid
from typing import Optional

import typer
from rich.console import Console

console = Console()
app = typer.Typer(rich_markup_mode="rich")

# Files/directories to remove for zero-day detection
CLEANUP_COMMANDS = [
    # Remove pre-existing PoC
    "rm -f /tmp/poc",
    # Remove seed corpora generated for fuzzing
    "find /out -maxdepth 1 -type f -name '*seed_corpus*.zip' -delete 2>/dev/null || true",
    # Remove pre-existing fuzzing crashers anywhere in source tree
    "find /src -name 'crash-*' -delete 2>/dev/null || true",
    # Remove seed directories anywhere in source tree
    "find /src -type d -name 'seeds' -exec rm -rf {} + 2>/dev/null || true",
    # Remove git metadata to avoid leakage and reduce image size
    "find /src -type d -name '.git' -prune -exec rm -rf {} + 2>/dev/null || true",
]


def run_command(cmd: list[str], check: bool = True, capture: bool = True) -> subprocess.CompletedProcess:
    """Run a command and return the result."""
    return subprocess.run(
        cmd,
        capture_output=capture,
        text=True,
        check=check,
    )


def image_exists(image: str) -> bool:
    """Check if a Docker image exists locally."""
    result = run_command(["docker", "image", "inspect", image], check=False)
    return result.returncode == 0


def pull_image(image: str) -> bool:
    """Pull a Docker image."""
    console.print(f"[yellow]Pulling image {image}...[/yellow]")
    result = run_command(["docker", "pull", image], check=False, capture=False)
    return result.returncode == 0


@app.command()
def main(
    image: str = typer.Option(
        ...,
        "--image",
        "-i",
        help="ARVO Docker image to clean (e.g., n132/arvo:14935-vul).",
    ),
    output_tag: Optional[str] = typer.Option(
        None,
        "--output-tag",
        "-o",
        help="Output image tag (defaults to <image>-clean).",
    ),
    dry_run: bool = typer.Option(
        False,
        "--dry-run",
        help="Show what would be removed without making changes.",
    ),
    keep_container: bool = typer.Option(
        False,
        "--keep-container",
        help="Keep the intermediate container (for debugging).",
    ),
) -> None:
    """Clean an ARVO Docker image for zero-day vulnerability detection."""
    
    # Determine output tag
    if output_tag is None:
        if "-vul" in image:
            output_tag = image.replace("-vul", "-vul-clean")
        elif "-fix" in image:
            output_tag = image.replace("-fix", "-fix-clean")
        else:
            output_tag = f"{image}-clean"
    
    console.print(f"[bold cyan]Input image:[/bold cyan] {image}")
    console.print(f"[bold cyan]Output image:[/bold cyan] {output_tag}")
    console.print()
    
    # Check if image exists, pull if needed
    if not image_exists(image):
        console.print(f"[yellow]Image not found locally, pulling...[/yellow]")
        if not pull_image(image):
            console.print(f"[bold red]Failed to pull image: {image}[/bold red]")
            raise typer.Exit(1)
    
    # Dry run: just show what would be removed
    if dry_run:
        console.print("[bold]Dry run - checking what would be removed:[/bold]")
        container_name = f"vulagent-clean-{uuid.uuid4().hex[:8]}"
        
        try:
            # Start container
            run_command([
                "docker", "run", "-d", "--name", container_name,
                image, "sleep", "60"
            ])
            
            # Check each cleanup target
            check_commands = [
                ("Pre-existing PoC", "ls -la /tmp/poc 2>/dev/null || echo 'Not found'"),
                ("Seed corpus", "find /out -maxdepth 1 -type f -name '*seed_corpus*.zip' 2>/dev/null | head -10 || echo 'None'"),
                ("Crashers", "find /src -name 'crash-*' 2>/dev/null | head -10 || echo 'None'"),
                ("Seeds dirs", "find /src -type d -name 'seeds' 2>/dev/null | head -10 || echo 'None'"),
                ("Git dirs", "find /src -type d -name '.git' 2>/dev/null | head -10 || echo 'None'"),
            ]
            
            for name, cmd in check_commands:
                result = run_command([
                    "docker", "exec", container_name, "bash", "-c", cmd
                ], check=False)
                console.print(f"\n[bold]{name}:[/bold]")
                console.print(result.stdout.strip() if result.stdout else "(empty)")
            
        finally:
            run_command(["docker", "rm", "-f", container_name], check=False)
        
        console.print("\n[dim]No changes made (dry run)[/dim]")
        return
    
    # Actual cleanup
    console.print("[bold]Cleaning image...[/bold]")
    container_name = f"vulagent-clean-{uuid.uuid4().hex[:8]}"
    
    try:
        # Start container
        console.print(f"[dim]Starting container from {image}...[/dim]")
        run_command([
            "docker", "run", "-d", "--name", container_name,
            image, "sleep", "300"
        ])
        
        # Run cleanup commands
        for cmd in CLEANUP_COMMANDS:
            console.print(f"[dim]Running: {cmd}[/dim]")
            run_command([
                "docker", "exec", container_name, "bash", "-c", cmd
            ], check=False)
        
        # Commit the cleaned container as a new image
        console.print(f"[dim]Committing as {output_tag}...[/dim]")
        run_command([
            "docker", "commit", container_name, output_tag
        ])
        
        console.print()
        console.print("[bold green]✓ Image cleaned successfully![/bold green]")
        console.print(f"[bold cyan]New image:[/bold cyan] {output_tag}")
        console.print()
        console.print("Usage:")
        console.print(f"  python -m vulagent.run.detect --arvo {output_tag}")
        
    finally:
        if not keep_container:
            run_command(["docker", "rm", "-f", container_name], check=False)


if __name__ == "__main__":
    app()
