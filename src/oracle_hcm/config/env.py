"""Automatic loading of the .env file.

Keys live in .env and nowhere else. The file is read into the process
environment at start-up; its contents are never printed, logged or returned
to a caller. Existing environment variables win over the file, so an operator
can always override a value from the shell.
"""

from __future__ import annotations

from pathlib import Path

from dotenv import load_dotenv

from oracle_hcm.paths import project_root

__all__ = ["env_file_path", "load_env"]


def env_file_path() -> Path:
    """Location of the .env file."""
    return project_root() / ".env"


def load_env(path: Path | None = None, *, override: bool = False) -> bool:
    """Load .env into the process environment.

    Returns True when a file was found and loaded. The file is optional: a
    missing .env is not an error, the engine simply starts without keys.
    """
    target = path if path is not None else env_file_path()
    if not target.is_file():
        return False
    load_dotenv(dotenv_path=target, override=override, encoding="utf-8")
    return True
