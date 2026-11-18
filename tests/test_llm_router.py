"""LLM router: no live calls, keys only at call time."""

from __future__ import annotations

import logging
from pathlib import Path

import pytest

from oracle_hcm.config.models import (
    ModelOverride,
    ModelRegistry,
    ModelRole,
    ModelSpec,
    load_model_registry,
)
from oracle_hcm.config.providers import Provider
from oracle_hcm.config.settings import Settings
from oracle_hcm.errors import (
    LLMCallError,
    MissingApiKeyError,
    ModelNotConfiguredError,
    RateLimitError,
)
from oracle_hcm.llm.limits import DailyTokenCounter, RateLimiter
from oracle_hcm.llm.router import CompletionRequest, LLMRouter, RawCompletion
from oracle_hcm.log.conversation import ConversationStore

CODER_MODEL = "nvidia_nim/qwen/qwen3-32b"


class FakeBackend:
    """Records calls and replays scripted results."""

    def __init__(self, results: list[RawCompletion | Exception]) -> None:
        self.results = list(results)
        self.calls: list[dict[str, object]] = []

    def __call__(
        self,
        *,
        model: str,
        messages: list[dict[str, str]],
        api_key: str,
        temperature: float | None = None,
        max_tokens: int | None = None,
        timeout: float = 90.0,
        **kwargs: object,
    ) -> RawCompletion:
        call: dict[str, object] = {
            "model": model,
            "api_key": api_key,
            "max_tokens": max_tokens,
            "timeout": timeout,
        }
        if temperature is not None:
            call["temperature"] = temperature
        call.update(kwargs)
        self.calls.append(call)
        result = self.results.pop(0) if self.results else RawCompletion(text="ok")
        if isinstance(result, Exception):
            raise result
        return result


def _request(role: ModelRole = ModelRole.CODER) -> CompletionRequest:
    return CompletionRequest(role=role, messages=[{"role": "user", "content": "hello"}])


def _router(
    backend: FakeBackend,
    registry: ModelRegistry,
    settings: Settings,
    **kwargs: object,
) -> LLMRouter:
    defaults: dict[str, object] = {"backoff_base": 0.0, "max_attempts": 3}
    defaults.update(kwargs)
    return LLMRouter(registry=registry, settings=settings, backend=backend, **defaults)  # type: ignore[arg-type]


def test_router_constructs_without_any_key(registry: ModelRegistry) -> None:
    router = _router(FakeBackend([]), registry, Settings.from_env({}))
    assert router is not None


async def test_missing_key_raises_only_when_a_model_is_called(
    registry: ModelRegistry,
) -> None:
    router = _router(FakeBackend([RawCompletion(text="never")]), registry, Settings.from_env({}))
    with pytest.raises(MissingApiKeyError):
        await router.complete(_request())


async def test_placeholder_model_is_refused(registry: ModelRegistry) -> None:
    placeholder = ModelRegistry(
        roles={ModelRole.CODER: ModelSpec(model="REPLACE_WITH_CODER_MODEL_ID")}
    )
    router = _router(FakeBackend([]), placeholder, Settings.from_env({}))
    with pytest.raises(ModelNotConfiguredError):
        await router.complete(_request())


async def test_a_placeholder_fallback_is_skipped_and_never_called(
    registry: ModelRegistry,
    settings_with_keys: Settings,
    caplog: pytest.LogCaptureFixture,
) -> None:
    with_placeholder = ModelRegistry(
        roles={
            **registry.roles,
            ModelRole.CODER: ModelSpec(
                model=CODER_MODEL,
                provider=Provider.NIM,
                fallback=("REPLACE_WITH_CODER_FALLBACK_MODEL_ID",),
            ),
        }
    )
    backend = FakeBackend([RuntimeError("primary down")] * 3)
    router = _router(backend, with_placeholder, settings_with_keys)

    with caplog.at_level(logging.WARNING), pytest.raises(LLMCallError):
        await router.complete(_request())

    assert [call["model"] for call in backend.calls] == [CODER_MODEL] * 3
    warnings = [record.getMessage() for record in caplog.records]
    assert any("placeholder" in message for message in warnings)
    assert any("coder" in message for message in warnings)


async def test_successful_call_returns_the_completion(
    registry: ModelRegistry, settings_with_keys: Settings
) -> None:
    backend = FakeBackend([RawCompletion(text="done", prompt_tokens=7, completion_tokens=3)])
    router = _router(backend, registry, settings_with_keys)

    completion = await router.complete(_request())

    assert completion.text == "done"
    assert completion.total_tokens == 10
    assert completion.provider == Provider.NIM.value
    assert completion.attempts == 1
    assert backend.calls[0]["model"] == "nvidia_nim/qwen/qwen3-32b"


async def test_a_placeholder_primary_is_skipped_and_the_fallback_runs(
    settings_with_keys: Settings,
) -> None:
    """The test designer waits for its Gemma model and runs on OpenAI."""
    registry = ModelRegistry(
        roles={
            ModelRole.TEST_DESIGNER: ModelSpec(
                model="REPLACE_WITH_GEMMA_4_31B_ID",
                provider=Provider.GEMINI,
                fallback=("openai/gpt-4.1",),
                rpm=30,
                tpm=16000,
            ),
        },
    )
    backend = FakeBackend([RawCompletion(text="from the fallback")])
    router = _router(backend, registry, settings_with_keys)

    completion = await router.complete(_request(ModelRole.TEST_DESIGNER))

    assert completion.text == "from the fallback"
    assert completion.model == "openai/gpt-4.1"
    assert completion.provider == Provider.OPENAI.value
    assert [call["model"] for call in backend.calls] == ["openai/gpt-4.1"]


async def test_temperature_override_is_forwarded(
    registry: ModelRegistry, settings_with_keys: Settings
) -> None:
    backend = FakeBackend([RawCompletion(text="x")])
    router = _router(backend, registry, settings_with_keys)

    await router.complete(CompletionRequest(role=ModelRole.CODER, messages=[], temperature=0.5))

    assert backend.calls[0]["temperature"] == 0.5


async def test_failures_fall_back_to_the_next_model(
    registry: ModelRegistry, settings_with_keys: Settings
) -> None:
    backend = FakeBackend(
        [
            RuntimeError("primary down"),
            RuntimeError("primary down"),
            RuntimeError("primary down"),
            RawCompletion(text="from fallback", prompt_tokens=1, completion_tokens=1),
        ]
    )
    router = _router(backend, registry, settings_with_keys)

    completion = await router.complete(_request(ModelRole.TEST_DESIGNER))

    assert completion.text == "from fallback"
    assert completion.model == "gemini/gemini-2.5-flash"
    assert completion.attempts == 4


async def test_all_models_failing_raises(
    registry: ModelRegistry, settings_with_keys: Settings
) -> None:
    backend = FakeBackend([RuntimeError("boom")] * 6)
    router = _router(backend, registry, settings_with_keys)

    with pytest.raises(LLMCallError) as error:
        await router.complete(_request(ModelRole.TEST_DESIGNER))

    message = str(error.value)
    assert "openai/gpt-4.1-mini (RuntimeError)" in message
    assert "gemini/gemini-2.5-flash (RuntimeError)" in message
    assert message.index("openai/gpt-4.1-mini") < message.index("gemini/gemini-2.5-flash")
    assert len(error.value.candidates) == 2


async def test_call_is_recorded_in_the_conversation_store(
    registry: ModelRegistry, settings_with_keys: Settings, tmp_path: Path
) -> None:
    store = ConversationStore(tmp_path / "conversations")
    backend = FakeBackend([RawCompletion(text="answer", prompt_tokens=2, completion_tokens=1)])
    router = _router(backend, registry, settings_with_keys, conversation_store=store)

    await router.complete(_request())

    records = store.read_all()
    assert len(records) == 1
    assert records[0].role == "coder"
    assert records[0].total_tokens == 3
    assert store.text_for(records[0].response_hash) == "answer"


async def test_daily_token_counter_tracks_usage(
    registry: ModelRegistry, settings_with_keys: Settings, tmp_path: Path
) -> None:
    counter = DailyTokenCounter(tmp_path / "tokens.json")
    backend = FakeBackend([RawCompletion(text="x", prompt_tokens=5, completion_tokens=5)])
    router = _router(backend, registry, settings_with_keys, counter=counter)

    await router.complete(_request())

    assert counter.total() == 10
    assert counter.total("nvidia_nim/qwen/qwen3-32b") == 10


def test_daily_budget_is_enforced(tmp_path: Path) -> None:
    counter = DailyTokenCounter(tmp_path / "tokens.json", daily_budget=5)
    counter.add("model", 5)
    with pytest.raises(RateLimitError):
        counter.check_budget(1)


def test_rate_limiter_blocks_a_second_request_in_the_window() -> None:
    limiter = RateLimiter(window_seconds=60.0)
    assert limiter.wait_time("m", rpm=1, tpm=0) == 0.0
    limiter.record("m")
    assert limiter.wait_time("m", rpm=1, tpm=0) > 0.0


def test_rate_limiter_blocks_on_tokens() -> None:
    limiter = RateLimiter(window_seconds=60.0)
    limiter.record("m", tokens=100)
    assert limiter.wait_time("m", rpm=0, tpm=100, tokens=10) > 0.0
    assert limiter.wait_time("m", rpm=0, tpm=1000, tokens=10) == 0.0


async def test_router_waits_for_the_rate_limit_before_calling(
    registry: ModelRegistry, settings_with_keys: Settings
) -> None:
    backend = FakeBackend([RawCompletion(text="a"), RawCompletion(text="b")])
    slow_registry = ModelRegistry(
        roles={
            **registry.roles,
            ModelRole.CODER: ModelSpec(
                model="nvidia_nim/qwen/qwen3-32b", provider=Provider.NIM, rpm=1, tpm=0
            ),
        }
    )
    router = _router(
        backend,
        slow_registry,
        settings_with_keys,
        limiter=RateLimiter(window_seconds=0.05),
    )

    await router.complete(_request())
    await router.complete(_request())

    assert len(backend.calls) == 2


async def test_model_override_drops_temperature_for_configured_model_only(
    settings_with_keys: Settings,
) -> None:
    backend = FakeBackend([RawCompletion(text="ok1"), RawCompletion(text="ok2")])
    registry = ModelRegistry(
        roles={
            ModelRole.REQUIREMENTS: ModelSpec(
                model="gemini/gemini-3.8-flash",
                provider=Provider.GEMINI,
                temperature=1.0,
            ),
            ModelRole.CODER: ModelSpec(
                model="nvidia_nim/qwen/qwen3-32b",
                provider=Provider.NIM,
                temperature=0.7,
            ),
        },
        model_overrides={
            "gemini/gemini-3.8-flash": ModelOverride(drop_params=("temperature",)),
        },
    )
    router = _router(backend, registry, settings_with_keys)

    await router.complete(CompletionRequest(role=ModelRole.REQUIREMENTS, messages=[]))
    assert backend.calls[0]["model"] == "gemini/gemini-3.8-flash"
    assert "temperature" not in backend.calls[0]
    assert backend.calls[0]["timeout"] == 90.0

    await router.complete(CompletionRequest(role=ModelRole.CODER, messages=[]))
    assert backend.calls[1]["model"] == "nvidia_nim/qwen/qwen3-32b"
    assert backend.calls[1]["temperature"] == 0.7
    assert backend.calls[1]["timeout"] == 90.0


async def test_request_timeout_is_configurable_and_passed_through(
    registry: ModelRegistry, settings_with_keys: Settings
) -> None:
    backend = FakeBackend([RawCompletion(text="ok1"), RawCompletion(text="ok2")])
    router = _router(backend, registry, settings_with_keys, request_timeout=45.0)

    await router.complete(_request())
    assert backend.calls[0]["timeout"] == 45.0

    await router.complete(CompletionRequest(role=ModelRole.CODER, messages=[], timeout=15.0))
    assert backend.calls[1]["timeout"] == 15.0


def test_models_yaml_contains_gemini_38_flash_override() -> None:
    registry = load_model_registry()
    override = registry.overrides_for("gemini/gemini-3.8-flash")
    assert "temperature" in override.drop_params


async def test_run_token_cap_raises_rate_limit_error(
    registry: ModelRegistry, settings_with_keys: Settings
) -> None:
    """A counter with a tiny budget raises RateLimitError before the first real call."""
    # Budget of 1 token is immediately exceeded by any projected cost check
    counter = DailyTokenCounter(daily_budget=1)
    # Manually exhaust the budget
    counter.add("any", 2)
    backend = FakeBackend([RawCompletion(text="should not reach")])
    router = LLMRouter(
        registry=registry,
        settings=settings_with_keys,
        backend=backend,
        counter=counter,
    )
    with pytest.raises(RateLimitError):
        await router.complete(_request())


async def test_slow_primary_falls_back_after_one_attempt(
    registry: ModelRegistry, settings_with_keys: Settings
) -> None:
    """The router allows at most 1 attempt per model by default before falling back."""
    backend = FakeBackend(
        [
            RuntimeError("primary failed once"),
            RawCompletion(text="from fallback", prompt_tokens=1, completion_tokens=1),
        ]
    )
    # Use default max_attempts (1)
    router = LLMRouter(registry=registry, settings=settings_with_keys, backend=backend)
    completion = await router.complete(_request(ModelRole.TEST_DESIGNER))
    assert completion.text == "from fallback"
    assert completion.attempts == 2
    assert backend.calls[0]["model"] == "openai/gpt-4.1-mini"
    assert backend.calls[1]["model"] == "gemini/gemini-2.5-flash"


async def test_call_chain_total_time_budget_exceeded(
    registry: ModelRegistry, settings_with_keys: Settings
) -> None:
    """A total time budget per call chain raises a clear error when exceeded."""
    import time

    class SlowBackend:
        def __call__(self, *args: object, **kwargs: object) -> RawCompletion:
            time.sleep(0.05)
            raise RuntimeError("slow failure")

    router = LLMRouter(
        registry=registry,
        settings=settings_with_keys,
        backend=SlowBackend(),
        chain_timeout=0.03,
    )
    with pytest.raises(LLMCallError, match="call chain time budget"):
        await router.complete(_request())


async def test_failed_model_calls_are_recorded(
    registry: ModelRegistry, settings_with_keys: Settings, tmp_path: Path
) -> None:
    store = ConversationStore(tmp_path / "failed-conversations")
    backend = FakeBackend([RuntimeError("model unavailable"), RuntimeError("fallback unavailable")])
    router = _router(
        backend,
        registry,
        settings_with_keys,
        conversation_store=store,
        max_attempts=1,
    )

    with pytest.raises(LLMCallError):
        await router.complete(_request(ModelRole.TEST_DESIGNER))

    records = store.read_all()
    assert {record.model for record in records} == {
        "openai/gpt-4.1-mini",
        "gemini/gemini-2.5-flash",
    }
    assert all(record.metadata["error_type"] == "RuntimeError" for record in records)
    assert all(record.metadata["error"] for record in records)
    assert all(record.latency_ms >= 0 for record in records)
    assert [record.attempt for record in records] == [1, 1]
