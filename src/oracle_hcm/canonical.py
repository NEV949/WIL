"""Deterministic JSON serialisation used for hashing and signing."""

from __future__ import annotations

import json
from typing import Any

__all__ = ["canonical_bytes", "canonical_json", "sha256_hex"]


def canonical_json(value: Any) -> str:
    """Serialise to JSON with sorted keys and no insignificant whitespace."""
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=str,
    )


def canonical_bytes(value: Any) -> bytes:
    return canonical_json(value).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    import hashlib

    return hashlib.sha256(data).hexdigest()
