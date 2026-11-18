"""LiteLLM router.

Resolves a role to its model chain, enforces per-model rate limits and a daily
token budget, retries with exponential backoff and records every call in the
conversation store. A provider key is required only when a model is actually
invoked.
"""

from __future__ import annotations

import asyncio
import logging
import time
import uuid
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any, Protocol

from oracle_hcm.config.models import PLACEHOLDER_PREFIX, ModelRegistry, ModelRole
from oracle_hcm.config.providers import Provider
from oracle_hcm.config.settings import Settings
from oracle_hcm.errors import (
    ConfigurationError,
    LLMCallError,
    MissingApiKeyError,
    ModelNotConfiguredError,
    RateLimitError,
)
from oracle_hcm.llm.limits import DailyTokenCounter, RateLimiter
from oracle_hcm.log.conversation import ConversationStore
from oracle_hcm.log.eventlog import EventLog

__all__ = [
    "Completion",
    "CompletionBackend",
    "CompletionRequest",
    "LLMRouter",
    "LiteLLMBackend",
    "RawCompletion",
]

_LOGGER = logging.getLogger(__name__)


@dataclass(frozen=True)
class RawCompletion:
    """What a backend returns."""

    text: str
    prompt_tokens: int = 0
    completion_tokens: int = 0


class CompletionBackend(Protocol):
    """Transport used to reach a model."""

    def __call__(
        self,
        *,
        model: str,
        messages: list[dict[str, str]],
        api_key: str,
        temperature: float | None = ...,
        max_tokens: int | None = ...,
        timeout: float = ...,
        **kwargs: Any,
    ) -> RawCompletion: ...


@dataclass(frozen=True)
class CompletionRequest:
    """A request for one role."""

    role: ModelRole
    messages: list[dict[str, str]]
    temperature: float | None = None
    max_tokens: int | None = None
    timeout: float | None = None
    chain_timeout: float | None = None
    tenant_id: str = "default"
    correlation_id: str = ""
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def prompt_text(self) -> str:
        return "\n".join(str(message.get("content", "")) for message in self.messages)


@dataclass(frozen=True)
class Completion:
    """A successful model response."""

    text: str
    model: str
    provider: str
    prompt_tokens: int
    completion_tokens: int
    total_tokens: int
    latency_ms: int
    attempts: int


class LiteLLMBackend:
    """Calls a model through LiteLLM."""

    def __call__(
        self,
        *,
        model: str,
        messages: list[dict[str, str]],
        api_key: str,
        temperature: float | None = None,
        max_tokens: int | None = None,
        timeout: float = 90.0,
        **kwargs: Any,
    ) -> RawCompletion:
        import litellm

        call_kwargs: dict[str, Any] = {
            "model": model,
            "messages": messages,
            "api_key": api_key,
            "timeout": timeout,
            "num_retries": 0,
        }
        if temperature is not None:
            call_kwargs["temperature"] = temperature
        if max_tokens is not None:
            call_kwargs["max_tokens"] = max_tokens
        call_kwargs.update(kwargs)
        response = litellm.completion(**call_kwargs)
        choices = getattr(response, "choices", None) or []
        text = ""
        if choices:
            message = getattr(choices[0], "message", None)
            text = (getattr(message, "content", "") or "") if message is not None else ""
        usage = getattr(response, "usage", None)
        prompt_tokens = int(getattr(usage, "prompt_tokens", 0) or 0)
        completion_tokens = int(getattr(usage, "completion_tokens", 0) or 0)
        return RawCompletion(
            text=text,
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
        )


class LLMRouter:
    """Routes role requests to models with limits, retries and fallbacks."""

    def __init__(
        self,
        *,
        registry: ModelRegistry,
        settings: Settings,
        backend: CompletionBackend | None = None,
        limiter: RateLimiter | None = None,
        counter: DailyTokenCounter | None = None,
        conversation_store: ConversationStore | None = None,
        event_log: EventLog | None = None,
        max_attempts: int = 1,
        backoff_base: float = 0.5,
        max_backoff: float = 8.0,
        request_timeout: float | None = None,
        chain_timeout: float | None = None,
    ) -> None:
        self._registry = registry
        self._settings = settings
        self._backend: CompletionBackend = backend if backend is not None else LiteLLMBackend()
        self._limiter = limiter if limiter is not None else RateLimiter()
        self._counter = counter if counter is not None else DailyTokenCounter()
        self._store = conversation_store
        self._event_log = event_log
        self._max_attempts = max(1, max_attempts)
        self._backoff_base = backoff_base
        self._max_backoff = max_backoff
        self._request_timeout = (
            request_timeout
            if request_timeout is not None
            else getattr(settings, "request_timeout_seconds", 90.0)
        )
        self._chain_timeout = (
            chain_timeout
            if chain_timeout is not None
            else getattr(settings, "chain_timeout_seconds", 120.0)
        )

    @property
    def request_timeout(self) -> float:
        return self._request_timeout

    @property
    def chain_timeout(self) -> float:
        return self._chain_timeout

    def resolve(self, role: ModelRole) -> tuple[str, Provider]:
        """Model id and provider for a role, refusing placeholder ids."""
        spec = self._registry.require_configured(role)
        model = spec.configured_model
        provider = self._registry.provider_for(model)
        if provider is Provider.UNKNOWN:
            provider = spec.resolved_provider()
        if provider is Provider.UNKNOWN:
            raise ConfigurationError(
                f"cannot infer a provider for model '{model}' of role '{role.value}'"
            )
        return model, provider

    async def complete(self, request: CompletionRequest) -> Completion:
        """Run a request through the model's fallback chain."""
        spec = self._registry.require_configured(request.role)
        candidates = spec.candidates()
        if not candidates:
            raise ConfigurationError(f"no model configured for role '{request.role.value}'")

        chain_started = time.monotonic()
        chain_budget = (
            request.chain_timeout
            if request.chain_timeout is not None
            else self._chain_timeout
        )

        last_error: Exception | None = None
        total_attempts = 0
        candidate_failures: list[tuple[str, str, str]] = []
        for candidate in candidates:
            if candidate.startswith(PLACEHOLDER_PREFIX):
                _LOGGER.warning(
                    "skipping fallback model for role '%s': the id is still a placeholder",
                    request.role.value,
                )
                continue
            provider = self._registry.provider_for(candidate)
            if provider is Provider.UNKNOWN:
                provider = spec.resolved_provider()
            if provider is Provider.UNKNOWN:
                raise ConfigurationError(f"cannot infer a provider for model '{candidate}'")
            try:
                api_key = self._settings.require_api_key(provider)
            except MissingApiKeyError as exc:
                last_error = exc
                candidate_failures.append(
                    (candidate, type(exc).__name__, str(exc))
                )
                continue

            for attempt in range(1, self._max_attempts + 1):
                elapsed = time.monotonic() - chain_started
                remaining = chain_budget - elapsed
                if remaining <= 0:
                    raise LLMCallError(
                        f"call chain time budget of {chain_budget:.0f}s exceeded for role "
                        f"'{request.role.value}'",
                        candidates=candidate_failures,
                    )

                total_attempts += 1
                temperature = (
                    request.temperature if request.temperature is not None else spec.temperature
                )
                max_tokens = (
                    request.max_tokens if request.max_tokens is not None else spec.max_tokens
                )
                limits = spec.limits_for(candidate)
                started = time.monotonic()
                try:
                    wait = self._limiter.wait_time(
                        candidate, rpm=limits.rpm, tpm=limits.tpm, tokens=limits.tpm // 10
                    )
                    if wait > 0:
                        if wait > remaining:
                            raise LLMCallError(
                                f"call chain time budget of {chain_budget:.0f}s exceeded "
                                f"waiting for rate limit on role '{request.role.value}'",
                                candidates=candidate_failures,
                            )
                        await asyncio.sleep(wait)
                    self._limiter.record(candidate, tokens=limits.tpm // 10)
                    self._counter.check_budget(limits.tpm // 10)
                    started = time.monotonic()
                    timeout = (
                        request.timeout
                        if request.timeout is not None
                        else self._request_timeout
                    )
                    spent = time.monotonic() - chain_started
                    call_timeout = max(0.1, min(timeout, chain_budget - spent))
                    call_kwargs: dict[str, Any] = {
                        "model": candidate,
                        "messages": list(request.messages),
                        "api_key": api_key,
                        "temperature": temperature,
                        "max_tokens": max_tokens,
                        "timeout": call_timeout,
                    }
                    overrides = self._registry.overrides_for(candidate)
                    for param in overrides.drop_params:
                        call_kwargs.pop(param, None)

                    raw = self._backend(**call_kwargs)
                    latency_ms = int((time.monotonic() - started) * 1000)
                except RateLimitError as exc:
                    latency_ms = int((time.monotonic() - started) * 1000)
                    self._record_failure(request, candidate, provider, attempt, latency_ms, exc)
                    raise
                except LLMCallError as exc:
                    latency_ms = int((time.monotonic() - started) * 1000)
                    self._record_failure(request, candidate, provider, attempt, latency_ms, exc)
                    raise
                except Exception as exc:
                    last_error = exc
                    latency_ms = int((time.monotonic() - started) * 1000)
                    self._record_failure(request, candidate, provider, attempt, latency_ms, exc)
                    elapsed = time.monotonic() - chain_started
                    if elapsed >= chain_budget:
                        candidate_failures.append(
                            (candidate, type(exc).__name__, repr(exc))
                        )
                        raise LLMCallError(
                            f"call chain time budget of {chain_budget:.0f}s exceeded for role "
                            f"'{request.role.value}': {exc!r}",
                            candidates=candidate_failures,
                        ) from exc
                    if attempt < self._max_attempts:
                        delay = self._backoff_delay(attempt)
                        if elapsed + delay >= chain_budget:
                            candidate_failures.append(
                                (candidate, type(exc).__name__, repr(exc))
                            )
                            break
                        await asyncio.sleep(delay)
                        continue
                    candidate_failures.append(
                        (candidate, type(exc).__name__, repr(exc))
                    )
                    break

                self._counter.add(candidate, raw.prompt_tokens + raw.completion_tokens)
                self._record(request, candidate, provider, raw, attempt, latency_ms)
                return Completion(
                    text=raw.text,
                    model=candidate,
                    provider=provider.value,
                    prompt_tokens=raw.prompt_tokens,
                    completion_tokens=raw.completion_tokens,
                    total_tokens=raw.prompt_tokens + raw.completion_tokens,
                    latency_ms=latency_ms,
                    attempts=total_attempts,
                )

        if isinstance(last_error, MissingApiKeyError):
            raise last_error
        elapsed = time.monotonic() - chain_started
        if elapsed >= chain_budget:
            raise LLMCallError(
                f"call chain time budget of {chain_budget:.0f}s exceeded for role "
                f"'{request.role.value}': {last_error!r}",
                candidates=candidate_failures,
            ) from last_error
        raise LLMCallError(
            f"all models for role '{request.role.value}' failed: {last_error!r}",
            candidates=candidate_failures,
        ) from last_error

    def record_schema_failure(
        self,
        request: CompletionRequest,
        completion: Completion,
        error: str,
    ) -> None:
        """Record that a successful model response failed artifact validation."""
        if self._store is None:
            return
        self._store.store(
            tenant_id=request.tenant_id,
            role=request.role.value,
            model=completion.model,
            model_version=str(self._registry.version),
            parameters={"temperature": request.temperature, "max_tokens": request.max_tokens},
            attempt=completion.attempts,
            latency_ms=completion.latency_ms,
            correlation_id=request.correlation_id or uuid.uuid4().hex,
            run_id=str(request.metadata.get("run_id", "")),
            prompt=request.prompt_text(),
            response=completion.text,
            error_type="ValidationError",
            error=error,
            metadata={"failure_kind": "schema_validation", **dict(request.metadata)},
        )

    def _record_failure(
        self,
        request: CompletionRequest,
        model: str,
        provider: Provider,
        attempt: int,
        latency_ms: int,
        error: Exception,
    ) -> None:
        """Record a failed provider call without storing credentials."""
        if self._store is None:
            return
        self._store.store(
            tenant_id=request.tenant_id,
            role=request.role.value,
            model=model,
            model_version=str(self._registry.version),
            parameters={"temperature": request.temperature, "max_tokens": request.max_tokens},
            attempt=attempt,
            latency_ms=latency_ms,
            correlation_id=request.correlation_id or uuid.uuid4().hex,
            run_id=str(request.metadata.get("run_id", "")),
            prompt=request.prompt_text(),
            response="",
            error_type=type(error).__name__,
            error=str(error),
            metadata={
                "failure_kind": "model_call",
                "provider": provider.value,
                **dict(request.metadata),
            },
        )

    def _backoff_delay(self, attempt: int) -> float:
        return min(self._backoff_base * (2.0 ** (attempt - 1)), self._max_backoff)

    def _record(
        self,
        request: CompletionRequest,
        model: str,
        provider: Provider,
        raw: RawCompletion,
        attempt: int,
        latency_ms: int,
    ) -> None:
        """Write the call to the conversation store and to the audit log.

        The full text of the exchange is redacted and kept in files that are
        referenced by their hash; the audit log holds the hashes, so the text
        is reachable without putting it into the log itself.
        """
        if self._store is None:
            return
        correlation_id = request.correlation_id or uuid.uuid4().hex
        run_id = str(request.metadata.get("run_id", ""))
        record = self._store.store(
            tenant_id=request.tenant_id,
            role=request.role.value,
            model=model,
            model_version=str(self._registry.version),
            parameters={
                "temperature": request.temperature,
                "max_tokens": request.max_tokens,
            },
            attempt=attempt,
            latency_ms=latency_ms,
            correlation_id=correlation_id,
            run_id=run_id,
            prompt=request.prompt_text(),
            response=raw.text,
            prompt_tokens=raw.prompt_tokens,
            completion_tokens=raw.completion_tokens,
            metadata={"provider": provider.value, **dict(request.metadata)},
        )
        if self._event_log is None:
            return
        self._event_log.append(
            tenant_id=request.tenant_id,
            actor="orchestrator",
            action="model_called",
            payload={
                "correlation_id": correlation_id,
                "call_id": record.call_id,
                "run_id": record.run_id,
                "role": request.role.value,
                "model": model,
                "model_version": record.model_version,
                "attempt": record.attempt,
                "latency_ms": record.latency_ms,
                "prompt_hash": record.prompt_hash,
                "response_hash": record.response_hash,
                "total_tokens": record.total_tokens,
            },
        )


def missing_key_error(provider: Provider) -> MissingApiKeyError:
    """Helper for callers that want to surface a missing key explicitly."""
    return MissingApiKeyError(provider)


def not_configured_error(role: ModelRole, model: str) -> ModelNotConfiguredError:
    """Helper for callers that want to surface a placeholder model explicitly."""
    return ModelNotConfiguredError(role.value, model)
