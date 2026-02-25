"""
This file provides:

- Path settings for global config file & relative directories
- Version numbering
- Protocols for the core components of vul-agent.
  By the magic of protocols & duck typing, you can pretty much ignore them,
  unless you want the static type checking.
"""

__version__ = "0.0.1"

import os
from pathlib import Path
from typing import Any, Protocol

import dotenv
from platformdirs import user_config_dir
from rich.console import Console

from vulagent.utils.log import logger

package_dir = Path(__file__).resolve().parent

# Try to load .env from project root first, then fall back to global config
project_root = package_dir.parent.parent  # Go up from src/vulagent/ to project root
project_env_file = project_root / ".env"
global_config_dir = Path(os.getenv("GLOBAL_CONFIG_DIR") or user_config_dir("vul-agent"))
global_config_dir.mkdir(parents=True, exist_ok=True)
global_config_file = Path(global_config_dir) / ".env"

# Load .env files: project root first, then global config (project root takes precedence)
if project_env_file.exists():
    if not os.getenv("SILENT_STARTUP"):
        Console().print(
            f"👋 This is [bold green]vul-agent[/bold green] version [bold green]{__version__}[/bold green].\n"
            f"Loading config from [bold green]'{project_env_file}'[/bold green] (project root)"
        )
    dotenv.load_dotenv(dotenv_path=project_env_file, override=False)
elif global_config_file.exists():
    if not os.getenv("SILENT_STARTUP"):
        Console().print(
            f"👋 This is [bold green]vul-agent[/bold green] version [bold green]{__version__}[/bold green].\n"
            f"Loading global config from [bold green]'{global_config_file}'[/bold green]"
        )
    dotenv.load_dotenv(dotenv_path=global_config_file, override=False)
else:
    if not os.getenv("SILENT_STARTUP"):
        Console().print(
            f"👋 This is [bold green]vul-agent[/bold green] version [bold green]{__version__}[/bold green].\n"
            f"No .env file found (checked: {project_env_file}, {global_config_file})"
        )


# === Protocols ===
# You can ignore them unless you want static type checking.


class Model(Protocol):
    """Protocol for language models."""

    config: Any
    cost: float
    n_calls: int

    def query(self, messages: list[dict[str, str]], **kwargs) -> dict: ...

    def get_template_vars(self) -> dict[str, Any]: ...


class Environment(Protocol):
    """Protocol for execution environments."""

    config: Any

    def execute(self, command: str, cwd: str = "") -> dict[str, str]: ...

    def get_template_vars(self) -> dict[str, Any]: ...


class Agent(Protocol):
    """Protocol for agents."""

    model: Model
    env: Environment
    messages: list[dict[str, str]]
    config: Any

    def run(self, task: str, **kwargs) -> tuple[str, str]: ...


__all__ = [
    "Agent",
    "Model",
    "Environment",
    "package_dir",
    "__version__",
    "global_config_file",
    "global_config_dir",
    "logger",
]
