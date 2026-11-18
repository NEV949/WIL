"""Embeddings.

The engine embeds text behind an interface, so that the provider of the
embeddings can be chosen later without touching the rest of the engine. The
deterministic embedder is the one used by the tests and by the offline runs:
it hashes the words of a text into a fixed vector, so the same text always
produces the same vector, in every process and on every machine.

The real provider lives in ``litellm_embedding``. It sits behind the same
interface, so the choice of the provider is the only difference between the
two.
"""

from __future__ import annotations

import hashlib
import math
import re
from collections.abc import Sequence
from typing import Protocol

from oracle_hcm.redaction import scrub_text

__all__ = [
    "MAX_EMBED_CHARS",
    "DeterministicEmbedder",
    "Embedder",
    "prepare_text",
    "tokenize",
]

_TOKEN = re.compile(r"[a-z0-9]+")

MAX_EMBED_CHARS = 8_000
"""How many characters of one text reach the embedding service."""


def tokenize(text: str) -> list[str]:
    """The words of a text, lower cased."""
    return _TOKEN.findall(text.lower())


def prepare_text(text: str, *, limit: int = MAX_EMBED_CHARS) -> str:
    """The text as it may leave the host: redacted and capped.

    A secret or the personal data of an employee never reaches a provider,
    and no single text is long enough to push a request over its limit.
    """
    return scrub_text(text).strip()[:limit]


class Embedder(Protocol):
    """Turns text into vectors."""

    @property
    def name(self) -> str:
        """The name that tells the vectors of two embedders apart."""
        ...

    @property
    def dimensions(self) -> int:
        """The length of every vector."""
        ...

    def embed(self, texts: Sequence[str]) -> list[list[float]]: ...


class DeterministicEmbedder:
    """A fake embedder that hashes the words of a text."""

    def __init__(self, dimensions: int = 64) -> None:
        if dimensions < 8:
            raise ValueError("the embedder needs at least eight dimensions")
        self._dimensions = dimensions

    @property
    def name(self) -> str:
        return "deterministic"

    @property
    def dimensions(self) -> int:
        return self._dimensions

    def embed(self, texts: Sequence[str]) -> list[list[float]]:
        """The vector of every text."""
        return [self._embed_one(prepare_text(text)) for text in texts]

    def _embed_one(self, text: str) -> list[float]:
        vector = [0.0] * self._dimensions
        for token in tokenize(text):
            digest = hashlib.blake2b(token.encode("utf-8"), digest_size=8).digest()
            bucket = int.from_bytes(digest[:4], "big") % self._dimensions
            sign = 1.0 if digest[4] % 2 == 0 else -1.0
            vector[bucket] += sign
        norm = math.sqrt(sum(value * value for value in vector))
        if norm == 0.0:
            return vector
        return [value / norm for value in vector]
