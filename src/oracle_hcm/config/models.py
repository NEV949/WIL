"""Model registry: one model string per role, loaded from config/models.yaml."""

from __future__ import annotations

from enum import StrEnum
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, ConfigDict, Field

from oracle_hcm.config.providers import Provider, provider_for_model
from oracle_hcm.errors import ConfigurationError, ModelNotConfiguredError
from oracle_hcm.paths import config_dir

__all__ = [
    "PLACEHOLDER_PREFIX",
    "EmbeddingSpec",
    "ModelLimits",
    "ModelOverride",
    "ModelRegistry",
    "ModelRole",
    "ModelSpec",
    "load_model_registry",
]

PLACEHOLDER_PREFIX = "REPLACE_WITH_"


class ModelRole(StrEnum):
    """Roles that own a model assignment."""

    REQUIREMENTS = "requirements"
    CODER = "coder"
    DEBUGGER = "debugger"
    TEST_DESIGNER = "test_designer"


class ModelLimits(BaseModel):
    """The limits of one model."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    rpm: int = Field(default=60, ge=0)
    tpm: int = Field(default=100_000, ge=0)


class ModelSpec(BaseModel):
    """Model assignment for one role."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    model: str
    provider: Provider = Provider.UNKNOWN
    fallback: tuple[str, ...] = ()
    rpm: int = Field(default=60, ge=0)
    tpm: int = Field(default=100_000, ge=0)
    temperature: float = Field(default=0.2, ge=0.0, le=2.0)
    max_tokens: int | None = Field(default=None, ge=1)
    limits: dict[str, ModelLimits] = Field(default_factory=dict)

    @property
    def is_configured(self) -> bool:
        return not self.model.startswith(PLACEHOLDER_PREFIX)

    def resolved_provider(self) -> Provider:
        if self.provider is not Provider.UNKNOWN:
            return self.provider
        return provider_for_model(self.model)

    def candidates(self) -> tuple[str, ...]:
        """Primary model first, then the fallback chain."""
        return (self.model, *self.fallback)

    def configured_candidates(self) -> tuple[str, ...]:
        """The candidates whose id is not a placeholder."""
        return tuple(
            candidate
            for candidate in self.candidates()
            if not candidate.startswith(PLACEHOLDER_PREFIX)
        )

    @property
    def configured_model(self) -> str:
        """The model that will run: the primary, or the first usable fallback."""
        configured = self.configured_candidates()
        return configured[0] if configured else self.model

    def limits_for(self, model: str) -> ModelLimits:
        """The limits of one model of the chain.

        A model of the chain can have limits of its own: the limits of the
        role apply to a model that does not name any.
        """
        return self.limits.get(model, ModelLimits(rpm=self.rpm, tpm=self.tpm))


class EmbeddingSpec(BaseModel):
    """Model assignment for the embeddings of the knowledge store."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    model: str
    provider: Provider = Provider.UNKNOWN
    dimensions: int = Field(default=1536, ge=1)
    rpm: int = Field(default=100, ge=0)
    tpm: int = Field(default=40_000, ge=0)

    @property
    def is_configured(self) -> bool:
        return not self.model.startswith(PLACEHOLDER_PREFIX)

    def resolved_provider(self) -> Provider:
        if self.provider is not Provider.UNKNOWN:
            return self.provider
        return provider_for_model(self.model)


class ModelOverride(BaseModel):
    """Overrides for a specific model."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    drop_params: tuple[str, ...] = ()


class ModelRegistry(BaseModel):
    """All role assignments."""

    model_config = ConfigDict(extra="forbid")

    version: int = 1
    roles: dict[ModelRole, ModelSpec]
    embeddings: EmbeddingSpec | None = None
    model_overrides: dict[str, ModelOverride] = Field(default_factory=dict)

    def overrides_for(self, model: str) -> ModelOverride:
        return self.model_overrides.get(model, ModelOverride())

    def spec_for(self, role: ModelRole) -> ModelSpec:
        try:
            return self.roles[role]
        except KeyError as exc:
            raise ConfigurationError(f"no model configured for role '{role.value}'") from exc

    def require_configured(self, role: ModelRole) -> ModelSpec:
        """Return the spec, refusing a chain without a usable model.

        A placeholder primary is allowed as long as the chain holds a model
        that is configured: the router skips the placeholders and calls the
        first model that is ready.
        """
        spec = self.spec_for(role)
        if not spec.configured_candidates():
            raise ModelNotConfiguredError(role.value, spec.model)
        return spec

    def require_embeddings(self) -> EmbeddingSpec:
        """The embedding model of the knowledge store."""
        if self.embeddings is None:
            raise ConfigurationError("no embedding model is configured")
        return self.embeddings

    def provider_for(self, model: str) -> Provider:
        return provider_for_model(model)


def load_model_registry(path: Path | None = None) -> ModelRegistry:
    """Load config/models.yaml.

    Placeholder model ids are allowed here; they only fail when a model is
    actually invoked.
    """
    target = path if path is not None else config_dir() / "models.yaml"
    if not target.is_file():
        raise ConfigurationError(f"model registry not found: {target}")
    raw: Any = yaml.safe_load(target.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ConfigurationError(f"model registry must be a mapping: {target}")
    return ModelRegistry.model_validate(raw)
