"""Risk classification.

The tier of a run comes from three sources: the words in the requirement, the
code that was generated for it, and the tier the SOP was declared with. A tier
may only be raised, never lowered.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Final

from oracle_hcm.schemas.artifacts import RequirementSpec, RiskTier
from oracle_hcm.security.ast_policy import AstPolicy, Capability, PolicyResult, modules_of

__all__ = [
    "HIGH_RISK_KEYWORDS",
    "MEDIUM_RISK_KEYWORDS",
    "RiskAssessment",
    "RiskClassifier",
]

HIGH_RISK_KEYWORDS: Final[tuple[str, ...]] = (
    "payroll",
    "salary",
    "wage",
    "bonus",
    "compensation",
    "remuneration",
    "tax",
    "taxation",
    "vat",
    "balance",
    "settlement",
    "payout",
    "pension",
    "insurance",
    "invoice",
    "payment",
    "money",
    "currency",
    "access right",
    "access control",
    "permission",
    "privilege",
    "role assignment",
    "authorisation",
    "authorization",
    "grant",
    "revoke",
    "pii",
    "personal data",
    "personally identifiable",
    "gdpr",
    "ssn",
    "national id",
    "passport",
    "date of birth",
    "biometric",
    "deletion",
    "erase",
    "delete",
    "mutation",
    "write access",
    "data mutation",
)

MEDIUM_RISK_KEYWORDS: Final[tuple[str, ...]] = (
    "read",
    "query",
    "list",
    "fetch",
    "show",
    "display",
    "view",
    "report",
    "validate",
    "validation",
    "verify",
    "check",
    "audit",
    "export",
    "download",
    "search",
    "calculate",
    "compute",
)

_OBFUSCATION_CAPABILITIES: Final[frozenset[str]] = frozenset(
    {
        Capability.DYNAMIC_EXEC,
        Capability.OBFUSCATION,
        Capability.NETWORK,
        Capability.PROCESS,
    }
)


@dataclass(frozen=True)
class RiskAssessment:
    """The tier of a run and the signals that produced it."""

    tier: RiskTier
    signals: tuple[str, ...] = ()
    code_capabilities: frozenset[str] = field(default_factory=frozenset)

    @property
    def needs_human_approval(self) -> bool:
        return self.tier.at_least(RiskTier.HIGH)


def _matches(text: str, keyword: str) -> bool:
    pattern = re.escape(keyword).replace(r"\ ", r"[\s_-]+")
    return re.search(rf"(?<![a-z0-9]){pattern}(?![a-z0-9])", text) is not None


class RiskClassifier:
    """Turns a requirement and its code into a risk tier."""

    def __init__(self, policy: AstPolicy | None = None) -> None:
        self._policy = policy if policy is not None else AstPolicy()

    def classify(
        self,
        spec: RequirementSpec | None,
        sources: list[str] | None = None,
        *,
        code: str = "",
        path: str = "",
        files: Mapping[str, str] | None = None,
        declared_tier: RiskTier | None = None,
    ) -> RiskAssessment:
        """Classify a run.

        Every source can only raise the tier above the declared one.
        """
        signals: list[str] = []
        tier = declared_tier if declared_tier is not None else RiskTier.LOW

        text_parts = list(sources or [])
        if spec is not None:
            text_parts.extend(spec.risk_keywords)
            text_parts.extend(spec.domain_entities)
            text_parts.append(spec.title)
            text_parts.append(spec.description)
            text_parts.extend(spec.acceptance_criteria)
            text_parts.extend(spec.constraints)
        haystack = " ".join(part for part in text_parts if part).lower()

        for keyword in HIGH_RISK_KEYWORDS:
            if _matches(haystack, keyword):
                signals.append(f"keyword:{keyword}")
                tier = _raise(tier, RiskTier.HIGH)
                break

        if tier is not RiskTier.HIGH:
            for keyword in MEDIUM_RISK_KEYWORDS:
                if _matches(haystack, keyword):
                    signals.append(f"keyword:{keyword}")
                    tier = _raise(tier, RiskTier.MEDIUM)
                    break

        capabilities, sensitive = self._analyse_code(code, path, files)
        dangerous = capabilities & _OBFUSCATION_CAPABILITIES
        if dangerous:
            signals.extend(f"code:{name}" for name in sorted(dangerous))
            tier = _raise(tier, RiskTier.HIGH)
        if Capability.FILE_WRITE in capabilities:
            signals.append("code:file_write")
            tier = _raise(tier, RiskTier.MEDIUM)
        if sensitive:
            signals.append("code:sensitive_field")
            tier = _raise(tier, RiskTier.MEDIUM)

        return RiskAssessment(
            tier=tier,
            signals=tuple(signals),
            code_capabilities=capabilities,
        )

    def _analyse_code(
        self,
        code: str,
        path: str,
        files: Mapping[str, str] | None,
    ) -> tuple[frozenset[str], bool]:
        """Re-check the generated code with the AST policy."""
        sources: list[tuple[str, str]] = list(files.items()) if files else []
        if code:
            sources.append((path, code))
        local = modules_of([file_path for file_path, _ in sources])
        capabilities: set[str] = set()
        sensitive = False
        for file_path, source in sources:
            policy_result: PolicyResult = self._policy.analyze(source, file_path, local)
            capabilities.update(policy_result.capabilities)
            sensitive = sensitive or any(
                finding.rule == "S105-sensitive" for finding in policy_result.findings
            )
        return frozenset(capabilities), sensitive


def _raise(current: RiskTier, candidate: RiskTier) -> RiskTier:
    """Return the higher of two tiers."""
    return candidate if candidate.rank > current.rank else current
