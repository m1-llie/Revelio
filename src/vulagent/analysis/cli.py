"""CLI for the static argument-check analyzer."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .check_analyzer import (
    analyze_file,
    analyze_directory,
    format_text_report,
    format_json_report,
    format_summary,
)


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(
        description="Static analyzer: report what checks exist for each function parameter in C/C++ code.",
    )
    parser.add_argument(
        "paths", nargs="+",
        help="C/C++ files or directories to analyze",
    )
    parser.add_argument(
        "-f", "--format", choices=["text", "json", "summary"], default="text",
        help="Output format (default: text)",
    )
    parser.add_argument(
        "--all", action="store_true",
        help="Show all functions, not just those with unchecked params",
    )
    parser.add_argument(
        "--ext", nargs="+", default=None,
        help="File extensions to include (default: .c .cpp .cc .cxx .h .hpp)",
    )
    parser.add_argument(
        "--include-tests", action="store_true",
        help="Include files under test/ directories",
    )
    parser.add_argument(
        "--unchecked-only", action="store_true",
        help="Only list functions that have at least one unchecked parameter",
    )
    args = parser.parse_args(argv)

    extensions = set(args.ext) if args.ext else None
    results = []
    for p in args.paths:
        path = Path(p)
        if path.is_dir():
            results.extend(analyze_directory(path, extensions, skip_tests=not args.include_tests))
        elif path.is_file():
            results.extend(analyze_file(path))
        else:
            print(f"Warning: {p} not found, skipping", file=sys.stderr)

    if args.unchecked_only:
        results = [r for r in results if r.unchecked_params]

    if args.format == "json":
        print(format_json_report(results))
    elif args.format == "summary":
        print(format_summary(results))
    else:
        print(format_text_report(results, show_checked=args.all))


if __name__ == "__main__":
    main()
