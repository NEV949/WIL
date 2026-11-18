"""Engine-wide exception hierarchy."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from oracle_hcm.config.providers import Provider

__all__ = [
    "ConfigurationError",
    "EnvelopeVerificationError",
    "EventLogIntegrityError",
    "LLMCallError",
    "MissingApiKeyError",
    "ModelNotConfiguredError",
    "OracleHcmError",
    "RateLimitError",
    "SignatureVerificationError",
    "SigningError",
]


class OracleHcmError(Exception):
    """Base class for every error raised by the engine."""


class ConfigurationError(OracleHcmError):
    """Configuration is missing or inconsistent."""


class MissingApiKeyError(ConfigurationError):
    """A provider key is absent from the environment.

    Raised only when a model is actually invoked, never at start-up.
    """

    def __init__(self, provider: Provider) -> None:
        self.provider = provider
        super().__init__(f"no API key in the environment for provider '{provider.value}'")

class ModelNotConfiguredError(ConfigurationError):
    """The model id for a role is still a placeholder."""

    def __init__(self, role: str, model: str) -> None:
        self.role = role
        self.model = model
        super().__init__(f"model id for role '{role}' is not configured: '{model}'")


class SigningError(OracleHcmError):
    """Key material is missing or malformed."""


class SignatureVerificationError(SigningError):
    """A signature did not verify."""


class EnvelopeVerificationError(OracleHcmError):
    """A bus envelope failed signature, tenant or schema verification."""


class EventLogIntegrityError(OracleHcmError):
    """The hash chain of the audit log is broken."""


class RateLimitError(OracleHcmError):
    """A rate limit or token budget was exhausted."""


class LLMCallError(OracleHcmError):
    """A model call failed after exhausting retries and fallbacks.

    ``candidates`` holds the per-model failure log as a list of
    ``(model, error_type, detail)`` tuples, one entry per distinct candidate
    that was attempted (not per retry).
    """

    def __init__(
        self,
        message: str,
        candidates: list[tuple[str, str, str]] | None = None,
    ) -> None:
        self.candidates: list[tuple[str, str, str]] = candidates or []
        if self.candidates:
            failures = "; ".join(
                f"{model} ({error_type})" for model, error_type, _ in self.candidates
            )
            message = f"{message}; candidate failures: {failures}"
        super().__init__(message)
