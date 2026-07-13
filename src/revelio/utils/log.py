import logging
import os
from pathlib import Path

from rich.logging import RichHandler


def _setup_root_logger() -> None:
    logger = logging.getLogger("revelio")
    logger.setLevel(logging.DEBUG if os.getenv("REVELIO_DEBUG") else logging.INFO)
    _handler = RichHandler(
        show_path=False,
        show_time=False,
        show_level=False,
        markup=True,
    )
    _formatter = logging.Formatter("%(name)s: %(levelname)s: %(message)s")
    _handler.setFormatter(_formatter)
    logger.addHandler(_handler)


def set_verbose(verbose: bool) -> None:
    """Toggle DEBUG-level console logging (e.g. raw Docker commands, per-file
    cleanup steps) on or off. Off by default — this detail is noise for a
    normal run and clutters the curated step/spinner output in detect.py.
    """
    logging.getLogger("revelio").setLevel(logging.DEBUG if verbose else logging.INFO)


def add_file_handler(path: Path | str, level: int = logging.DEBUG, *, print_path: bool = True) -> None:
    logger = logging.getLogger("revelio")
    handler = logging.FileHandler(path)
    handler.setLevel(level)
    formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    if print_path:
        print(f"Logging to '{path}'")


_setup_root_logger()
logger = logging.getLogger("revelio")


__all__ = ["logger", "set_verbose"]
