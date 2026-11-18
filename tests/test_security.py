"""Secret redaction and environment-driven connection settings."""

from __future__ import annotations

import sys
from types import ModuleType
from typing import Any, ClassVar

import pytest

from oracle_hcm.bus.redis_streams import redis_url_from_env
from oracle_hcm.llm.router import LiteLLMBackend
from oracle_hcm.paths import config_dir, data_dir, keys_dir
from oracle_hcm.paths import project_root as project_root_path
from oracle_hcm.redaction import redact, redact_text


class TestRedaction:
    @pytest.mark.parametrize(
        "secret",
        [
            "sk-abcdefghijklmnopqrstuvwxyz012345",
            "sk-ant-abcdefghijklmnopqrstuvwxyz012345",
            "gsk_abcdefghijklmnopqrstuvwxyz012345",
            "nvapi-abcdefghijklmnopqrstuvwxyz012345",
            "AIzaAbcdefghijklmnopqrstuvwxyz012345",
        ],
    )
    def test_provider_keys_are_removed(self, secret: str) -> None:
        redacted = redact_text(f"the key is {secret} ok")
        assert secret not in redacted
        assert "[REDACTED]" in redacted

    def test_bearer_token_is_removed(self) -> None:
        redacted = redact_text("Authorization: Bearer abcdefghijklmnopqrstuvwxyz")
        assert "abcdefghijklmnopqrstuvwxyz" not in redacted

    def test_private_key_block_is_removed(self) -> None:
        pem = (
            "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkq\n-----END PRIVATE KEY-----"
        )
        redacted = redact_text(f"key material: {pem}")
        assert "MIIEvQIBADANBgkq" not in redacted

    def test_env_style_assignment_is_removed(self) -> None:
        redacted = redact_text("OPENAI_API_KEY=supersecretvalue")
        assert "supersecretvalue" not in redacted
        assert "OPENAI_API_KEY" in redacted

    def test_short_values_are_left_alone(self) -> None:
        assert redact_text("TOKEN=abc") == "TOKEN=abc"

    def test_plain_text_is_untouched(self) -> None:
        assert redact_text("nothing secret here") == "nothing secret here"

    def test_redact_walks_containers(self) -> None:
        payload = {
            "text": "key sk-abcdefghijklmnopqrstuvwxyz012345",
            "nested": [{"value": "gsk_abcdefghijklmnopqrstuvwxyz012345"}],
            "number": 7,
            "flag": True,
        }
        result = redact(payload)
        assert isinstance(result, dict)
        assert "sk-abcdefghijklmnopqrstuvwxyz012345" not in str(result)
        assert result["number"] == 7
        assert result["flag"] is True


class TestRedisUrl:
    def test_explicit_url_wins(self) -> None:
        url = redis_url_from_env({"REDIS_URL": "redis://host:6379/1", "REDIS_PASSWORD": "x"})
        assert url == "redis://host:6379/1"

    def test_password_is_used_when_no_url(self) -> None:
        url = redis_url_from_env({"REDIS_PASSWORD": "p@ss word"})
        assert "p%40ss%20word" in url
        assert url.startswith("redis://:")

    def test_local_default_without_password(self) -> None:
        assert redis_url_from_env({}) == "redis://127.0.0.1:6379/0"


class TestPaths:
    def test_paths_are_under_the_project_root(self, project_root: Any) -> None:
        assert config_dir().is_dir()
        assert data_dir().parent == project_root
        assert keys_dir().parent == project_root
        assert project_root_path().name == "3ce07929"


class TestLiteLLMBackend:
    def test_maps_the_litellm_response(self, monkeypatch: pytest.MonkeyPatch) -> None:
        class _Message:
            content = "hello"

        class _Choice:
            message = _Message()

        class _Usage:
            prompt_tokens = 11
            completion_tokens = 7

        class _Response:
            choices: ClassVar[list[_Choice]] = [_Choice()]
            usage = _Usage()

        captured: dict[str, Any] = {}

        def _completion(**kwargs: Any) -> _Response:
            captured.update(kwargs)
            return _Response()

        fake = ModuleType("litellm")
        fake.completion = _completion  # type: ignore[attr-defined]
        monkeypatch.setitem(sys.modules, "litellm", fake)

        result = LiteLLMBackend()(
            model="groq/openai/gpt-oss-120b",
            messages=[{"role": "user", "content": "hi"}],
            api_key="fake-key",
            temperature=0.1,
            max_tokens=64,
        )
        assert result.text == "hello"
        assert result.prompt_tokens == 11
        assert result.completion_tokens == 7
        assert captured["model"] == "groq/openai/gpt-oss-120b"
        assert captured["api_key"] == "fake-key"
        assert captured["max_tokens"] == 64

    def test_max_tokens_is_omitted_when_not_set(self, monkeypatch: pytest.MonkeyPatch) -> None:
        captured: dict[str, Any] = {}

        def _completion(**kwargs: Any) -> Any:
            captured.update(kwargs)
            return type("R", (), {"choices": [], "usage": None})()

        fake = ModuleType("litellm")
        fake.completion = _completion  # type: ignore[attr-defined]
        monkeypatch.setitem(sys.modules, "litellm", fake)

        result = LiteLLMBackend()(
            model="groq/openai/gpt-oss-120b",
            messages=[{"role": "user", "content": "hi"}],
            api_key="fake-key",
            temperature=0.0,
            max_tokens=None,
        )
        assert "max_tokens" not in captured
        assert result.text == ""
        assert result.prompt_tokens == 0
