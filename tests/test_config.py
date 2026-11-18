"""Settings and model registry."""

from __future__ import annotations

from pathlib import Path

import pytest

from oracle_hcm.config.models import (
    ModelLimits,
    ModelRegistry,
    ModelRole,
    ModelSpec,
    load_model_registry,
)
from oracle_hcm.config.providers import Provider, provider_for_model
from oracle_hcm.config.settings import Settings
from oracle_hcm.errors import ConfigurationError, MissingApiKeyError, ModelNotConfiguredError


def test_settings_start_without_any_key() -> None:
    settings = Settings.from_env({})
    assert settings.api_key(Provider.GROQ) is None
    assert settings.jwt_secret is None


def test_security_repair_attempt_limit_is_configurable() -> None:
    assert Settings.from_env({}).security_repair_attempts == 3
    configured = Settings.from_env({"ORACLE_HCM_SECURITY_REPAIR_ATTEMPTS": "5"})
    assert configured.security_repair_attempts == 5


def test_settings_read_keys_from_environment() -> None:
    settings = Settings.from_env({"GROQ_API_KEY": "value", "JWT_SECRET": "secret"})
    assert settings.api_key(Provider.GROQ) == "value"
    assert settings.jwt_secret == "secret"


def test_require_api_key_raises_when_absent() -> None:
    settings = Settings.from_env({})
    with pytest.raises(MissingApiKeyError):
        settings.require_api_key(Provider.OPENAI)


def test_settings_repr_does_not_leak_keys() -> None:
    settings = Settings.from_env({"GROQ_API_KEY": "super-secret"})
    assert "super-secret" not in repr(settings)


def test_provider_inference_from_model_prefix() -> None:
    assert provider_for_model("groq/openai/gpt-oss-120b") is Provider.GROQ
    assert provider_for_model("openai/gpt-4.1-mini") is Provider.OPENAI
    assert provider_for_model("gemini/gemini-2.5-flash") is Provider.GEMINI
    assert provider_for_model("nvidia_nim/minimax/minimax-m2") is Provider.NIM
    assert provider_for_model("mystery-model") is Provider.UNKNOWN


def test_registry_placeholder_is_allowed_until_call_time() -> None:
    spec = ModelSpec(model="REPLACE_WITH_CODER_MODEL_ID")
    assert spec.is_configured is False
    registry = ModelRegistry(roles={ModelRole.CODER: spec})
    with pytest.raises(ModelNotConfiguredError):
        registry.require_configured(ModelRole.CODER)


def test_a_placeholder_primary_with_a_configured_fallback_is_allowed() -> None:
    spec = ModelSpec(
        model="REPLACE_WITH_GEMMA_4_31B_ID",
        provider=Provider.GEMINI,
        fallback=("openai/gpt-4.1",),
        rpm=30,
        tpm=16000,
    )
    registry = ModelRegistry(roles={ModelRole.TEST_DESIGNER: spec})

    assert registry.require_configured(ModelRole.TEST_DESIGNER).model == (
        "REPLACE_WITH_GEMMA_4_31B_ID"
    )
    assert spec.configured_candidates() == ("openai/gpt-4.1",)
    assert spec.configured_model == "openai/gpt-4.1"


def test_a_model_of_the_chain_can_carry_limits_of_its_own() -> None:
    spec = ModelSpec(
        model="REPLACE_WITH_GEMMA_4_31B_ID",
        provider=Provider.GEMINI,
        fallback=("openai/gpt-4.1",),
        rpm=30,
        tpm=16000,
        limits={"openai/gpt-4.1": ModelLimits(rpm=3, tpm=10000)},
    )

    assert spec.limits_for("openai/gpt-4.1").rpm == 3
    assert spec.limits_for("openai/gpt-4.1").tpm == 10000
    assert spec.limits_for("REPLACE_WITH_GEMMA_4_31B_ID").rpm == 30
    assert spec.limits_for("REPLACE_WITH_GEMMA_4_31B_ID").tpm == 16000


def test_the_shipped_registry_names_the_embedding_model(project_root: Path) -> None:
    registry = load_model_registry(project_root / "config" / "models.yaml")

    spec = registry.require_embeddings()

    assert spec.model == "gemini/gemini-embedding-2"
    assert spec.provider is Provider.GEMINI
    assert spec.dimensions == 768
    assert spec.rpm == 100
    assert spec.tpm == 30000


def test_the_test_designer_waits_for_the_gemma_model(project_root: Path) -> None:
    registry = load_model_registry(project_root / "config" / "models.yaml")

    spec = registry.require_configured(ModelRole.TEST_DESIGNER)

    assert spec.model == "gemini/gemma-4-31b-it"
    assert spec.provider is Provider.GEMINI
    assert spec.fallback == (
        "groq/openai/gpt-oss-120b",
        "gemini/gemini-3.8-flash",
        "openai/gpt-4.1",
    )
    assert spec.rpm == 30
    assert spec.tpm == 16000
    assert spec.limits_for("groq/openai/gpt-oss-120b") == ModelLimits(rpm=30, tpm=8000)
    assert spec.limits_for("gemini/gemini-3.8-flash") == ModelLimits(rpm=5, tpm=250000)
    assert spec.limits_for("openai/gpt-4.1") == ModelLimits(rpm=3, tpm=10000)


def test_the_roles_have_expected_order_and_limits(project_root: Path) -> None:
    registry = load_model_registry(project_root / "config" / "models.yaml")

    req_spec = registry.require_configured(ModelRole.REQUIREMENTS)
    assert req_spec.model == "gemini/gemini-3.8-flash"
    assert req_spec.provider is Provider.GEMINI
    assert req_spec.rpm == 5
    assert req_spec.tpm == 250000
    assert req_spec.fallback == (
        "groq/openai/gpt-oss-120b",
        "nvidia_nim/minimaxai/minimax-m3.1-flash",
    )
    assert req_spec.limits_for("groq/openai/gpt-oss-120b") == ModelLimits(rpm=30, tpm=8000)
    assert req_spec.limits_for("nvidia_nim/minimaxai/minimax-m3.1-flash") == ModelLimits(
        rpm=35, tpm=120000
    )

    coder_spec = registry.require_configured(ModelRole.CODER)
    assert coder_spec.model == "groq/qwen/qwen3.8-27b"
    assert coder_spec.provider is Provider.GROQ
    assert coder_spec.rpm == 30
    assert coder_spec.tpm == 8000
    assert coder_spec.fallback == (
        "groq/openai/gpt-oss-120b",
        "gemini/gemini-3.8-flash",
        "nvidia_nim/minimaxai/minimax-m3.1-flash",
    )
    assert coder_spec.limits_for("groq/openai/gpt-oss-120b") == ModelLimits(rpm=30, tpm=8000)
    assert coder_spec.limits_for("gemini/gemini-3.8-flash") == ModelLimits(rpm=5, tpm=250000)
    assert coder_spec.limits_for("nvidia_nim/minimaxai/minimax-m3.1-flash") == ModelLimits(
        rpm=35, tpm=120000
    )

    dbg_spec = registry.require_configured(ModelRole.DEBUGGER)
    assert dbg_spec.model == "groq/openai/gpt-oss-120b"
    assert dbg_spec.provider is Provider.GROQ
    assert dbg_spec.rpm == 30
    assert dbg_spec.tpm == 8000
    assert dbg_spec.fallback == (
        "groq/qwen/qwen3.8-27b",
        "gemini/gemini-3.8-flash",
        "nvidia_nim/minimaxai/minimax-m3.1-flash",
    )
    assert dbg_spec.limits_for("groq/qwen/qwen3.8-27b") == ModelLimits(rpm=30, tpm=8000)
    assert dbg_spec.limits_for("gemini/gemini-3.8-flash") == ModelLimits(rpm=5, tpm=250000)
    assert dbg_spec.limits_for("nvidia_nim/minimaxai/minimax-m3.1-flash") == ModelLimits(
        rpm=35, tpm=120000
    )

    td_spec = registry.require_configured(ModelRole.TEST_DESIGNER)
    assert td_spec.model == "gemini/gemma-4-31b-it"
    assert td_spec.provider is Provider.GEMINI
    assert td_spec.rpm == 30
    assert td_spec.tpm == 16000
    assert td_spec.fallback == (
        "groq/openai/gpt-oss-120b",
        "gemini/gemini-3.8-flash",
        "openai/gpt-4.1",
    )
    assert td_spec.limits_for("groq/openai/gpt-oss-120b") == ModelLimits(rpm=30, tpm=8000)
    assert td_spec.limits_for("gemini/gemini-3.8-flash") == ModelLimits(rpm=5, tpm=250000)
    assert td_spec.limits_for("openai/gpt-4.1") == ModelLimits(rpm=3, tpm=10000)


def test_the_registry_without_an_embedding_model_says_so() -> None:
    registry = ModelRegistry(roles={})

    with pytest.raises(ConfigurationError):
        registry.require_embeddings()


def test_registry_requires_a_role() -> None:
    registry = ModelRegistry(roles={})
    with pytest.raises(ConfigurationError):
        registry.spec_for(ModelRole.CODER)


def test_shipped_registry_loads(project_root: Path) -> None:
    registry = load_model_registry(project_root / "config" / "models.yaml")
    assert set(registry.roles) == set(ModelRole)
    for role, spec in registry.roles.items():
        assert spec.model, role
        assert spec.candidates()[0] == spec.model


def test_spec_candidates_lists_fallbacks() -> None:
    spec = ModelSpec(model="a", fallback=("b", "c"))
    assert spec.candidates() == ("a", "b", "c")
