"""Filesystem locations used by the engine."""

from __future__ import annotations

import os
from pathlib import Path

__all__ = [
    "config_dir",
    "data_dir",
    "keys_dir",
    "project_root",
    "semgrep_rules_path",
    "sop_dir",
    "web_dist",
]


def project_root() -> Path:
    """Root of the repository.

    Overridable with ORACLE_HCM_ROOT so the engine can run from a deployment
    directory other than the checkout.
    """
    override = os.environ.get("ORACLE_HCM_ROOT")
    if override:
        return Path(override).resolve()
    return Path(__file__).resolve().parents[2]


def config_dir() -> Path:
    return project_root() / "config"


def sop_dir() -> Path:
    return config_dir() / "sops"


def semgrep_rules_path() -> Path:
    return config_dir() / "semgrep" / "oracle_rules.yml"


def data_dir() -> Path:
    return project_root() / "data"


def keys_dir() -> Path:
    return project_root() / "keys"


def web_dist() -> Path:
    """The build of the console."""
    return project_root() / "web" / "dist"
