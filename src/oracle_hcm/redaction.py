"""Redaction of secrets and personal data from text that leaves the trusted boundary.

The engine stores LLM transcripts and audit payloads. Those may quote keys
that a model hallucinated or that leaked through a retrieval snippet, so every
transcript is scrubbed before it is written to disk. Retrieved knowledge is
scrubbed on the way out as well, because a document of the store may carry
the personal data of an employee.
"""

from __future__ import annotations

import re

__all__ = ["redact", "redact_personal_text", "redact_text", "scrub_text"]

_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"\bsk-[A-Za-z0-9_\-]{16,}"),
    re.compile(r"\bsk-ant-[A-Za-z0-9_\-]{16,}"),
    re.compile(r"\bgsk_[A-Za-z0-9_\-]{16,}"),
    re.compile(r"\bnvapi-[A-Za-z0-9_\-]{16,}"),
    re.compile(r"\bAIza[A-Za-z0-9_\-]{16,}"),
    re.compile(r"\bBearer\s+[A-Za-z0-9._\-]{16,}"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.S),
    re.compile(
        r"(?i)\b([A-Z0-9_]*(?:API_KEY|SECRET|TOKEN|PASSWORD|PASSWD)\s*[:=]\s*)"
        r"([^\s\"',;]{4,})"
    ),
)

_PLACEHOLDER = "[REDACTED]"

_PERSONAL_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b"),
    re.compile(r"(?<!\d)\+?\d{2,3}[\s.-]\d{3,4}[\s.-]\d{4}(?!\d)"),
    re.compile(r"(?<![0-9A-Za-z])\d{17}[\dXx](?![0-9A-Za-z])"),
    re.compile(r"\b(?:\d{4}[ -]){3}\d{4}\b"),
)
"""Patterns of personal data: mail addresses, phone numbers, national ids."""


def redact_text(text: str) -> str:
    """Replace anything that looks like a credential with a fixed marker."""
    result = text
    for pattern in _PATTERNS:
        if pattern.groups:
            result = pattern.sub(lambda m: f"{m.group(1)}{_PLACEHOLDER}", result)
        else:
            result = pattern.sub(_PLACEHOLDER, result)
    return result


def redact_personal_text(text: str) -> str:
    """Replace anything that looks like personal data with a fixed marker."""
    result = text
    for pattern in _PERSONAL_PATTERNS:
        result = pattern.sub(_PLACEHOLDER, result)
    return result


def scrub_text(text: str) -> str:
    """Redact the secrets and the personal data of a text."""
    return redact_personal_text(redact_text(text))


def redact(payload: object) -> object:
    """Recursively redact strings inside a JSON-like structure."""
    if isinstance(payload, str):
        return redact_text(payload)
    if isinstance(payload, dict):
        return {key: redact(value) for key, value in payload.items()}
    if isinstance(payload, list):
        return [redact(item) for item in payload]
    if isinstance(payload, tuple):
        return tuple(redact(item) for item in payload)
    return payload
