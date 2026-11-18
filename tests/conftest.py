"""Shared fixtures."""

from __future__ import annotations

import os
import re
from pathlib import Path

import pytest

from oracle_hcm.config.models import ModelRegistry, ModelRole, ModelSpec
from oracle_hcm.config.providers import Provider
from oracle_hcm.config.settings import Settings
from oracle_hcm.signing.keys import KeyPair, generate_keypair
from oracle_hcm.signing.signer import Signer, Verifier

REAL_REQUIREMENTS_MODEL = "nvidia_nim/minimax/minimax-m2"
REAL_CODER_MODEL = "nvidia_nim/qwen/qwen3-32b"
REAL_DEBUGGER_MODEL = "groq/openai/gpt-oss-120b"
REAL_TEST_DESIGNER_MODEL = "openai/gpt-4.1-mini"


@pytest.fixture
def keypair() -> KeyPair:
    return generate_keypair()


@pytest.fixture
def signer(keypair: KeyPair) -> Signer:
    return Signer(keypair.private_key)


@pytest.fixture
def verifier(keypair: KeyPair) -> Verifier:
    return Verifier(keypair.public_key)


@pytest.fixture
def registry() -> ModelRegistry:
    return ModelRegistry(
        version=1,
        roles={
            ModelRole.REQUIREMENTS: ModelSpec(
                model=REAL_REQUIREMENTS_MODEL, provider=Provider.NIM, rpm=60, tpm=120_000
            ),
            ModelRole.CODER: ModelSpec(
                model=REAL_CODER_MODEL, provider=Provider.NIM, rpm=60, tpm=120_000
            ),
            ModelRole.DEBUGGER: ModelSpec(
                model=REAL_DEBUGGER_MODEL, provider=Provider.GROQ, rpm=30, tpm=60_000
            ),
            ModelRole.TEST_DESIGNER: ModelSpec(
                model=REAL_TEST_DESIGNER_MODEL,
                provider=Provider.OPENAI,
                fallback=("gemini/gemini-2.5-flash",),
                rpm=30,
                tpm=80_000,
            ),
        },
    )


@pytest.fixture
def settings_with_keys() -> Settings:
    return Settings.from_env(
        {
            "NVIDIA_NIM_API_KEY": "nim-test-key",
            "GROQ_API_KEY": "groq-test-key",
            "OPENAI_API_KEY": "openai-test-key",
            "GEMINI_API_KEY": "gemini-test-key",
            "JWT_SECRET": "jwt-test-secret",
        }
    )


@pytest.fixture
def settings_without_keys() -> Settings:
    return Settings.from_env({})


@pytest.fixture
def project_root() -> Path:
    return Path(__file__).resolve().parents[1]


@pytest.fixture
def redis_password(monkeypatch: pytest.MonkeyPatch) -> str | None:
    """Expose the Redis password to the bus tests.

    The value comes from the environment, or from the default declared in
    infra/docker-compose.yml. Nothing is hard coded here.
    """
    from_env = os.environ.get("REDIS_PASSWORD")
    if from_env:
        monkeypatch.setenv("REDIS_PASSWORD", from_env)
        return from_env
    compose = Path(__file__).resolve().parents[1] / "infra" / "docker-compose.yml"
    if not compose.is_file():
        return None
    match = re.search(r"REDIS_PASSWORD:-([^}\s]+)", compose.read_text(encoding="utf-8"))
    if not match:
        return None
    password = match.group(1)
    monkeypatch.setenv("REDIS_PASSWORD", password)
    return password
