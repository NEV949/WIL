"""Configuration package."""

from __future__ import annotations

from oracle_hcm.config.models import (
    EmbeddingSpec,
    ModelLimits,
    ModelRegistry,
    ModelRole,
    ModelSpec,
    load_model_registry,
)
from oracle_hcm.config.providers import Provider, provider_for_model
from oracle_hcm.config.settings import Settings

__all__ = [
    "EmbeddingSpec",
    "ModelLimits",
    "ModelRegistry",
    "ModelRole",
    "ModelSpec",
    "Provider",
    "Settings",
    "load_model_registry",
    "provider_for_model",
]
