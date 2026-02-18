#!/usr/bin/env python3
"""Summarize common failure modes across all failure_analysis.md reports.

Reads every failure_analysis.md written by analyze_failures.py, feeds them
all to an LLM, and produces a structured summary of recurring failure patterns.

Examples:
    # Summarize all found analyses, write to output/failure_summary.md
    python scripts/summarize_failures.py

    # Scan a specific output tree
    python scripts/summarize_failures.py --output-dir output/batch_file_scan

    # Print to stdout instead of writing a file
    python scripts/summarize_failures.py --stdout
"""

from __future__ import annotations

from pathlib import Path

import anthropic
import typer
from rich.console import Console

console = Console()
app = typer.Typer(rich_markup_mode="rich", pretty_exceptions_show_locals=False)

REPO_ROOT = Path(__file__).parent.parent
DEFAULT_OUTPUT_DIRS = ["output/batch_claude_code", "output/batch_file_scan"]
DEFAULT_SUMMARY_PATH = REPO_ROOT / "output" / "failure_summary.md"


def collect_analyses(output_dirs: list[Path]) -> list[dict]:
    entries = []
    for out_dir in output_dirs:
        if not out_dir.is_dir():
            continue
        for cve_dir in sorted(out_dir.iterdir()):
            report = cve_dir / "failure_analysis.md"
            if report.exists():
                entries.append({
                    "cve_id": cve_dir.name,
                    "source": out_dir.name,
                    "text": report.read_text(),
                })
    return entries


def build_prompt(analyses: list[dict]) -> tuple[str, str]:
    system = """\
You are an expert security researcher synthesizing failure analyses from an \
AI agent that attempted to localize vulnerabilities in source code.

Your task is to read all per-CVE failure analyses and produce a high-quality \
summary that identifies recurring, cross-cutting failure modes. Think carefully \
before writing — look for patterns that appear in multiple CVEs, not just \
surface-level category labels.
"""

    # Build the corpus
    corpus_parts = []
    for e in analyses:
        corpus_parts.append(
            f"## [{e['source']}] {e['cve_id']}\n\n{e['text'].strip()}"
        )
    corpus = "\n\n---\n\n".join(corpus_parts)

    user = f"""\
Below are {len(analyses)} individual failure analyses for an AI agent that \
tried to localize vulnerable lines in CVE-affected source code. Each analysis \
covers: root cause, key mistakes, what the agent should have done, and a \
category classification.

{corpus}

---

## Your Task

Synthesize these analyses into a concise, actionable failure mode report. \
Structure your response exactly as follows:

---

# Failure Mode Summary

## Overview
(2–4 sentences: How many CVEs, what output directories, overall picture of \
where the agent tends to fail.)

## Common Failure Modes

For each failure mode you identify (aim for 4–7 distinct modes), use this format:

### <Mode Name>
**Frequency:** X / {len(analyses)} cases
**Affected CVEs:** <list of CVE IDs>
**Description:** What this failure mode looks like in practice.
**Root Pattern:** The underlying cognitive or search strategy failure that \
causes it.
**Example:** A concrete excerpt or paraphrase from one of the analyses above.

## Category Distribution
A table showing how often each Category label appeared across all analyses \
(labels: wrong_hypothesis, insufficient_exploration, misread_code, \
context_misunderstanding, correct_area_wrong_lines, other).

## Key Takeaways
3–5 bullet points: the most important actionable insights for improving the \
agent's localization strategy.
"""
    return system, user


@app.command()
def main(
    output_dir: list[str] = typer.Option(
        DEFAULT_OUTPUT_DIRS,
        "--output-dir", "-o",
        help="Output directories to scan (relative to repo root). Repeat for multiple.",
    ),
    out_file: Path = typer.Option(
        DEFAULT_SUMMARY_PATH,
        "--out-file", "-f",
        help="Where to write the summary Markdown.",
    ),
    model: str = typer.Option(
        "claude-opus-4-6",
        "--model", "-m",
        help="Claude model to use.",
    ),
    stdout: bool = typer.Option(
        False,
        "--stdout",
        help="Print summary to stdout instead of writing a file.",
    ),
) -> None:
    """Summarize common failure modes across all failure_analysis.md reports."""

    resolved_dirs = [
        (REPO_ROOT / d) if not Path(d).is_absolute() else Path(d)
        for d in output_dir
    ]

    analyses = collect_analyses(resolved_dirs)
    if not analyses:
        console.print("[red]No failure_analysis.md files found.[/red] Run analyze_failures.py first.")
        raise typer.Exit(1)

    console.print(f"Found [bold]{len(analyses)}[/bold] analyses across {[str(d) for d in resolved_dirs]}")
    for e in analyses:
        console.print(f"  [cyan]{e['source']}[/cyan]  {e['cve_id']}")

    console.print(f"\nCalling [bold]{model}[/bold] to synthesize...")

    client = anthropic.Anthropic()
    system, user = build_prompt(analyses)

    response = client.messages.create(
        model=model,
        max_tokens=4096,
        system=system,
        messages=[{"role": "user", "content": user}],
    )
    summary = response.content[0].text

    if stdout:
        console.print("\n" + summary)
    else:
        out_file.parent.mkdir(parents=True, exist_ok=True)
        out_file.write_text(summary + "\n")
        console.print(f"\n[green]Written to:[/green] {out_file}")


if __name__ == "__main__":
    app()
