"""Loading SOP definitions from YAML."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml
from pydantic import ValidationError

from oracle_hcm.errors import ConfigurationError
from oracle_hcm.paths import sop_dir
from oracle_hcm.sop.models import SopDefinition

__all__ = ["load_sop", "load_sops"]


def load_sop(path: Path) -> SopDefinition:
    """Load and validate one SOP file."""
    if not path.is_file():
        raise ConfigurationError(f"SOP file not found: {path}")
    raw: Any = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ConfigurationError(f"SOP file must contain a mapping: {path}")
    try:
        return SopDefinition.model_validate(raw)
    except ValidationError as exc:
        raise ConfigurationError(f"invalid SOP file {path}: {exc}") from exc


def load_sops(directory: Path | None = None) -> dict[str, SopDefinition]:
    """Load every SOP in a directory, keyed by sop_id."""
    target = directory if directory is not None else sop_dir()
    if not target.is_dir():
        raise ConfigurationError(f"SOP directory not found: {target}")
    definitions: dict[str, SopDefinition] = {}
    for path in sorted(target.glob("*.yaml")):
        definition = load_sop(path)
        definitions[definition.sop_id] = definition
    if not definitions:
        raise ConfigurationError(f"no SOP definitions found in {target}")
    return definitions
