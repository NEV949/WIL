"""Prompt Guard.

The requirement text is attacker controlled: it arrives from an operator, a
ticket or a chat message. Before it reaches an agent it is checked for
instructions that try to bend the rules. The check sits behind an interface so
a hosted Guard service can replace the local pattern matcher.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Final, Protocol

__all__ = [
    "FakePromptGuard",
    "GuardVerdict",
    "PromptGuardClient",
    "RegexPromptGuard",
]


@dataclass(frozen=True)
class GuardVerdict:
    """What the guard decided about one piece of text."""

    blocked: bool
    signals: tuple[str, ...] = ()
    categories: tuple[str, ...] = ()

    @property
    def clean(self) -> bool:
        return not self.blocked


class PromptGuardClient(Protocol):
    """Interface every prompt guard implementation must satisfy."""

    async def inspect(self, text: str) -> GuardVerdict: ...


@dataclass(frozen=True)
class _Pattern:
    """One instruction pattern the guard looks for."""

    category: str
    signal: str
    pattern: str
    blocking: bool = True


_PATTERNS: Final[tuple[_Pattern, ...]] = (
    _Pattern(
        "prompt_injection",
        "ignores previous instructions",
        r"\bignore\s+(?:all\s+|any\s+)?(?:the\s+)?(?:previous|prior|earlier|above|foregoing)\b"
        r"\s+(?:instructions?|prompts?|rules?|directions?)",
    ),
    _Pattern(
        "prompt_injection",
        "disregards previous instructions",
        r"\bdisregard\s+(?:all\s+|any\s+)?(?:the\s+)?(?:previous|prior|earlier|above)\b"
        r"\s+(?:instructions?|prompts?|rules?)",
    ),
    _Pattern(
        "prompt_injection",
        "forgets the instructions",
        r"\bforget\s+(?:everything|all\s+previous|your\s+instructions|the\s+rules)\b",
    ),
    _Pattern(
        "role_override",
        "takes over the assistant role",
        r"\byou\s+are\s+now\s+(?:a|an|the|in)\b",
    ),
    _Pattern(
        "role_override",
        "pretends to be another system",
        r"\b(?:act|behave|respond)\s+as\s+(?:if\s+you\s+are\s+)?(?:a|an|the)\s+"
        r"(?:unrestricted|jailbroken|developer\s+mode)\b",
    ),
    _Pattern(
        "prompt_exfiltration",
        "asks for the system prompt",
        r"\b(?:reveal|show|print|repeat|output|leak)\b[^.]{0,40}\b(?:system\s+prompt"
        r"|system\s+message|your\s+instructions|the\s+prompt)\b",
    ),
    _Pattern(
        "exfiltration",
        "asks for secrets",
        r"\b(?:reveal|show|print|send|email|upload|exfiltrate|leak|dump)\b[^.]{0,40}"
        r"\b(?:api[\s_-]?keys?|secrets?|passwords?|tokens?|\.env\b|credentials?)\b",
    ),
    _Pattern(
        "concealment",
        "asks to hide the activity",
        r"\bdo\s+not\s+(?:tell|mention|inform|notify|log|report\s+to)\b",
    ),
    _Pattern(
        "concealment",
        "asks to bypass the review",
        r"\b(?:skip|bypass|disable|turn\s+off)\b[^.]{0,30}\b(?:approval|review|gate|"
        r"validation|security|test)\b",
    ),
    _Pattern(
        "network_instruction",
        "asks for an outbound request",
        r"\b(?:curl|wget|fetch\s+from|download\s+from)\b[^.]{0,20}https?://",
        blocking=False,
    ),
    _Pattern(
        "obfuscation",
        "asks for obfuscated code",
        r"\bbase64\b[^.]{0,20}\b(?:decode|exec|payload)\b",
        blocking=False,
    ),
    _Pattern(
        "tool_abuse",
        "asks for a destructive command",
        r"\brm\s+-rf\b|\bmkfs\b|\bdd\s+if=/dev/(?:zero|urandom)\b",
        blocking=False,
    ),
)


class RegexPromptGuard:
    """Local guard that matches the instruction patterns."""

    def __init__(self, patterns: tuple[_Pattern, ...] | None = None) -> None:
        self._patterns = patterns if patterns is not None else _PATTERNS

    async def inspect(self, text: str) -> GuardVerdict:
        """Check one text."""
        signals: list[str] = []
        categories: list[str] = []
        blocked = False
        for pattern in self._patterns:
            if re.search(pattern.pattern, text, flags=re.IGNORECASE):
                signals.append(pattern.signal)
                if pattern.category not in categories:
                    categories.append(pattern.category)
                blocked = blocked or pattern.blocking
        return GuardVerdict(blocked=blocked, signals=tuple(signals), categories=tuple(categories))


@dataclass
class FakePromptGuard:
    """Scripted guard used in tests and when no service is configured."""

    verdicts: dict[str, GuardVerdict] = field(default_factory=dict)
    default: GuardVerdict = GuardVerdict(blocked=False)
    calls: list[str] = field(default_factory=list)

    async def inspect(self, text: str) -> GuardVerdict:
        """Return the scripted verdict for this text."""
        self.calls.append(text)
        for marker, verdict in self.verdicts.items():
            if marker in text:
                return verdict
        return self.default
