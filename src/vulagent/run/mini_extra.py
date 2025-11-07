#!/usr/bin/env python3

import sys
from importlib import import_module

from rich.console import Console

subcommands = [
    ("vulagent.run.extra.config", ["config"], "Manage the global config file"),
    ("vulagent.run.inspector", ["inspect", "i", "inspector"], "Run inspector (browse trajectories)"),
]


def get_docstring() -> str:
    lines = [
        "This is the [yellow]central entry point for all extra commands[/yellow] from vul-agent.",
        "",
        "Available sub-commands:",
        "",
    ]
    for _, aliases, description in subcommands:
        alias_text = " or ".join(f"[bold green]{alias}[/bold green]" for alias in aliases)
        lines.append(f"  {alias_text}: {description}")
    return "\n".join(lines)


def main():
    args = sys.argv[1:]

    if len(args) == 0 or len(args) == 1 and args[0] in ["-h", "--help"]:
        return Console().print(get_docstring())

    for module_path, aliases, _ in subcommands:
        if args[0] in aliases:
            return import_module(module_path).app(args[1:], prog_name=f"mini-extra {aliases[0]}")

    return Console().print(get_docstring())


if __name__ == "__main__":
    main()
