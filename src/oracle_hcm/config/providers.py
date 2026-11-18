"""Model providers and the environment variables that carry their keys."""

from __future__ import annotations

from enum import StrEnum

__all__ = [
    "LITELLM_PROVIDER_NAMES",
    "MODEL_PREFIX_TO_PROVIDER",
    "PROVIDER_ENV_VARS",
    "Provider",
    "provider_for_model",
]


class Provider(StrEnum):
    """Upstream inference providers used by the LiteLLM router."""

    NIM = "nim"
    GROQ = "groq"
    OPENAI = "openai"
    GEMINI = "gemini"
    FAKE = "fake"
    UNKNOWN = "unknown"


PROVIDER_ENV_VARS: dict[Provider, str] = {
    Provider.NIM: "NVIDIA_NIM_API_KEY",
    Provider.GROQ: "GROQ_API_KEY",
    Provider.OPENAI: "OPENAI_API_KEY",
    Provider.GEMINI: "GEMINI_API_KEY",
}

LITELLM_PROVIDER_NAMES: dict[Provider, str] = {
    Provider.NIM: "nvidia_nim",
    Provider.GROQ: "groq",
    Provider.OPENAI: "openai",
    Provider.GEMINI: "gemini",
    Provider.FAKE: "fake",
    Provider.UNKNOWN: "unknown",
}
"""The name LiteLLM knows a provider under."""

MODEL_PREFIX_TO_PROVIDER: dict[str, Provider] = {
    "groq/": Provider.GROQ,
    "openai/": Provider.OPENAI,
    "gemini/": Provider.GEMINI,
    "google/": Provider.GEMINI,
    "vertex_ai/": Provider.GEMINI,
    "nvidia_nim/": Provider.NIM,
    "nvidia/": Provider.NIM,
    "nim/": Provider.NIM,
    "fake/": Provider.FAKE,
}


def provider_for_model(model: str) -> Provider:
    """Infer the provider from a LiteLLM model string prefix."""
    lowered = model.lower()
    for prefix, provider in MODEL_PREFIX_TO_PROVIDER.items():
        if lowered.startswith(prefix):
            return provider
    return Provider.UNKNOWN
