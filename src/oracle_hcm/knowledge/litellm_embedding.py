"""The embedder that reaches a provider through LiteLLM.

The engine can embed its text with a real model instead of the deterministic
one. The embedder sits behind the same interface, so nothing else in the
engine changes when the provider changes.

The model id, the provider, the limits and the length of the vectors come
from the "embeddings" section of config/models.yaml. The key is read from the
environment only when a text is embedded, so the engine starts and runs
without one and a missing key surfaces at the moment of the call.

Every text is redacted and capped before it leaves the host. The texts are
sent in batches, the requests are held to the sliding window of the configured
limits, and a transient failure of the service is retried with an exponential
backoff.
"""

from __future__ import annotations

import logging
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import Any, Protocol

from oracle_hcm.config.models import PLACEHOLDER_PREFIX, EmbeddingSpec
from oracle_hcm.config.providers import LITELLM_PROVIDER_NAMES, Provider, provider_for_model
from oracle_hcm.config.settings import Settings
from oracle_hcm.errors import (
    ConfigurationError,
    LLMCallError,
    MissingApiKeyError,
    ModelNotConfiguredError,
)
from oracle_hcm.knowledge.embeddings import prepare_text
from oracle_hcm.llm.limits import RateLimiter

__all__ = [
    "DEFAULT_BACKOFF_BASE",
    "DEFAULT_BATCH_SIZE",
    "DEFAULT_EMBEDDING_MODEL",
    "DEFAULT_MAX_ATTEMPTS",
    "DEFAULT_MAX_BACKOFF",
    "DEFAULT_RPM",
    "DEFAULT_TPM",
    "EMBEDDING_DIMENSIONS",
    "EmbeddingBackend",
    "EmbeddingResponse",
    "LiteLLMEmbedder",
    "LiteLLMEmbeddingBackend",
    "OpenAIEmbedder",
    "build_embedder",
    "effective_provider",
    "estimate_tokens",
]

_LOGGER = logging.getLogger(__name__)

DEFAULT_EMBEDDING_MODEL = "text-embedding-3-small"
EMBEDDING_DIMENSIONS = 1536
"""The length of the vectors of the default model."""

DEFAULT_RPM = 100
DEFAULT_TPM = 40_000
DEFAULT_BATCH_SIZE = 64
DEFAULT_MAX_ATTEMPTS = 4
DEFAULT_BACKOFF_BASE = 0.5
DEFAULT_MAX_BACKOFF = 8.0

CHARS_PER_TOKEN = 4
"""How many characters one token of the service counts for."""

OPENAI_EMBEDDING_PROVIDERS = frozenset({"openai", "together_ai", "nvidia_nim", "litellm_proxy"})
"""The providers whose embeddings LiteLLM sends through the OpenAI client."""

_RETRYABLE_NAMES = (
    "RateLimit",
    "Timeout",
    "ServiceUnavailable",
    "InternalServer",
    "Overloaded",
    "APIConnection",
)
"""The names of the errors that are worth another attempt."""


@dataclass(frozen=True)
class EmbeddingResponse:
    """What the embedding service returns."""

    vectors: list[list[float]]
    total_tokens: int = 0


class EmbeddingBackend(Protocol):
    """Transport used to reach the embedding service."""

    def __call__(
        self, *, model: str, inputs: list[str], api_key: str, dimensions: int
    ) -> EmbeddingResponse: ...


def effective_provider(model: str, configured: Provider) -> Provider:
    """The provider that serves the model.

    The prefix of the model id decides, so the engine and LiteLLM agree on
    the provider and on the key that is used. The configured provider decides
    when the model id carries no prefix.
    """
    if "/" not in model:
        return configured
    found = provider_for_model(model)
    if found is not Provider.UNKNOWN:
        return found
    return configured


class LiteLLMEmbeddingBackend:
    """Calls the embedding service through LiteLLM."""

    def __init__(self, *, provider: Provider = Provider.UNKNOWN, timeout: float = 60.0) -> None:
        self._provider = provider
        self._timeout = timeout
        self._clients: dict[tuple[str, str, str], Any] = {}

    def __call__(
        self, *, model: str, inputs: list[str], api_key: str, dimensions: int
    ) -> EmbeddingResponse:
        import litellm

        # LiteLLM prints a banner on every failure; the engine reports the
        # failure itself and does not need the banner.
        litellm.suppress_debug_info = True
        custom = _custom_provider(model, self._provider)
        response = litellm.embedding(
            model=model,
            input=inputs,
            api_key=api_key,
            dimensions=dimensions,
            timeout=self._timeout,
            custom_llm_provider=custom,
            client=self._client(model, api_key, custom),
        )
        data = list(getattr(response, "data", None) or [])
        data.sort(key=lambda item: _index_of(item))
        usage = getattr(response, "usage", None)
        return EmbeddingResponse(
            vectors=[_vector_of(item) for item in data],
            total_tokens=int(getattr(usage, "total_tokens", 0) or 0),
        )

    def _client(self, model: str, api_key: str, custom: str | None) -> Any:
        """The client of the provider.

        The environment of the host carries a NO_PROXY list with an IPv6
        entry that the http client cannot parse, so the client is told to
        ignore the proxy settings of the environment: the provider is
        reached directly.
        """
        provider = effective_provider(model, self._provider)
        name = LITELLM_PROVIDER_NAMES.get(provider, provider.value)
        key = (name, model, api_key)
        client = self._clients.get(key)
        if client is None:
            client = self._build_client(name, model, api_key, custom)
            self._clients[key] = client
        return client

    def _build_client(
        self, name: str, model: str, api_key: str, custom: str | None
    ) -> Any:
        """The client of a provider.

        The providers of the OpenAI family are reached with the client of the
        OpenAI library, the other ones with the client of LiteLLM.
        """
        if name in OPENAI_EMBEDDING_PROVIDERS:
            import httpx2
            from openai import OpenAI

            return OpenAI(
                api_key=api_key,
                base_url=_api_base(model, api_key, custom),
                http_client=httpx2.Client(trust_env=False),
                timeout=self._timeout,
                max_retries=0,
            )
        import httpx
        from litellm.llms.custom_httpx.http_handler import HTTPHandler

        return HTTPHandler(client=httpx.Client(trust_env=False), timeout=self._timeout)


class LiteLLMEmbedder:
    """Embeds text with the embedding model of the configuration."""

    def __init__(
        self,
        *,
        model: str,
        dimensions: int = EMBEDDING_DIMENSIONS,
        provider: Provider = Provider.UNKNOWN,
        settings: Settings | None = None,
        backend: EmbeddingBackend | None = None,
        limiter: RateLimiter | None = None,
        batch_size: int = DEFAULT_BATCH_SIZE,
        rpm: int = DEFAULT_RPM,
        tpm: int = DEFAULT_TPM,
        max_attempts: int = DEFAULT_MAX_ATTEMPTS,
        backoff_base: float = DEFAULT_BACKOFF_BASE,
        max_backoff: float = DEFAULT_MAX_BACKOFF,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        if batch_size < 1:
            raise ValueError("the batch size must be at least one")
        if dimensions < 1:
            raise ValueError("the vector size must be at least one")
        self._model = model
        self._dimensions = dimensions
        self._provider = provider
        self._settings = settings
        self._backend: EmbeddingBackend = (
            backend if backend is not None else LiteLLMEmbeddingBackend(provider=provider)
        )
        self._limiter = limiter if limiter is not None else RateLimiter()
        self._batch_size = batch_size
        self._rpm = rpm
        self._tpm = tpm
        self._max_attempts = max(1, max_attempts)
        self._backoff_base = backoff_base
        self._max_backoff = max_backoff
        self._sleep = sleep

    @property
    def name(self) -> str:
        """The name that tells the vectors of this embedder apart."""
        if "/" in self._model:
            return self._model
        provider = self._provider.value
        return f"{provider}/{self._model}" if provider != "unknown" else self._model

    @property
    def dimensions(self) -> int:
        return self._dimensions

    @property
    def model(self) -> str:
        """The model id that is sent to the service."""
        return self._model

    @property
    def provider(self) -> Provider:
        """The provider that serves the model."""
        return effective_provider(self._model, self._provider)

    def embed(self, texts: Sequence[str]) -> list[list[float]]:
        """The vector of every text, in batches."""
        if self._model.startswith(PLACEHOLDER_PREFIX):
            raise ModelNotConfiguredError("embeddings", self._model)
        prepared = [prepare_text(text) for text in texts]
        if not prepared:
            return []
        vectors: list[list[float]] = []
        for start in range(0, len(prepared), self._batch_size):
            vectors.extend(self._embed_batch(prepared[start : start + self._batch_size]))
        return vectors

    def _embed_batch(self, batch: list[str]) -> list[list[float]]:
        """The vectors of one batch, with the limits and the backoff."""
        key = self._api_key()
        estimated = estimate_tokens(batch)
        for attempt in range(1, self._max_attempts + 1):
            try:
                wait = self._limiter.wait_time(
                    self.name, rpm=self._rpm, tpm=self._tpm, tokens=estimated
                )
                if wait > 0:
                    self._sleep(wait)
                self._limiter.record(self.name, tokens=estimated)
                response = self._backend(
                    model=self._model,
                    inputs=list(batch),
                    api_key=key,
                    dimensions=self._dimensions,
                )
            except MissingApiKeyError:
                raise
            except Exception as exc:
                if attempt >= self._max_attempts or not _is_retryable(exc):
                    raise LLMCallError(
                        f"the embedding model '{self._model}' failed: {exc}"
                    ) from exc
                delay = self._backoff(attempt)
                _LOGGER.warning(
                    "the embedding model '%s' failed (%s), another attempt in %.1fs",
                    self._model,
                    type(exc).__name__,
                    delay,
                )
                self._sleep(delay)
                continue
            return self._vectors_of(response, len(batch), estimated)
        raise LLMCallError(f"the embedding model '{self._model}' failed")

    def _vectors_of(
        self, response: EmbeddingResponse, expected: int, estimated: int
    ) -> list[list[float]]:
        """The vectors of a response, checked against the size of the embedder."""
        if len(response.vectors) != expected:
            raise LLMCallError(
                f"the embedding model '{self._model}' returned {len(response.vectors)} "
                f"vectors for {expected} texts"
            )
        vectors: list[list[float]] = []
        for vector in response.vectors:
            if len(vector) != self._dimensions:
                raise LLMCallError(
                    f"the embedding model '{self._model}' returned a vector of "
                    f"{len(vector)} dimensions, the embedder expects {self._dimensions}"
                )
            vectors.append(list(vector))
        if response.total_tokens > estimated:
            self._limiter.record_tokens(self.name, response.total_tokens - estimated)
        return vectors

    def _api_key(self) -> str:
        """The key of the provider, read when the call is made."""
        provider = self.provider
        if provider is Provider.UNKNOWN:
            raise ConfigurationError(
                f"cannot infer the provider of the embedding model '{self._model}'"
            )
        settings = self._settings if self._settings is not None else Settings.from_env()
        return settings.require_api_key(provider)

    def _backoff(self, attempt: int) -> float:
        return min(self._backoff_base * (2.0 ** (attempt - 1)), self._max_backoff)


class OpenAIEmbedder(LiteLLMEmbedder):
    """Embeds text with the OpenAI embedding model."""

    def __init__(
        self,
        *,
        model: str = DEFAULT_EMBEDDING_MODEL,
        dimensions: int = EMBEDDING_DIMENSIONS,
        provider: Provider = Provider.OPENAI,
        **kwargs: Any,
    ) -> None:
        super().__init__(model=model, dimensions=dimensions, provider=provider, **kwargs)


def build_embedder(
    spec: EmbeddingSpec,
    *,
    settings: Settings | None = None,
    backend: EmbeddingBackend | None = None,
    limiter: RateLimiter | None = None,
    sleep: Callable[[float], None] = time.sleep,
) -> LiteLLMEmbedder:
    """The embedder of the embeddings section of the configuration."""
    return LiteLLMEmbedder(
        model=spec.model,
        dimensions=spec.dimensions,
        provider=spec.resolved_provider(),
        rpm=spec.rpm,
        tpm=spec.tpm,
        settings=settings,
        backend=backend,
        limiter=limiter,
        sleep=sleep,
    )


def estimate_tokens(texts: Sequence[str]) -> int:
    """How many tokens the texts of a batch are worth."""
    return sum(max(1, len(text) // CHARS_PER_TOKEN) for text in texts)


def _custom_provider(model: str, provider: Provider) -> str | None:
    """The provider LiteLLM is told about.

    A model id that carries a prefix is routed by LiteLLM itself; a bare id
    needs the name of the provider.
    """
    if "/" in model:
        return None
    name = LITELLM_PROVIDER_NAMES.get(provider)
    return name if name not in (None, "unknown") else None


def _api_base(model: str, api_key: str, custom: str | None) -> str | None:
    """The address of the provider, as LiteLLM resolves it."""
    import litellm

    try:
        resolved = litellm.get_llm_provider(
            model=model, custom_llm_provider=custom, api_key=api_key
        )
    except Exception:
        return None
    api_base = resolved[3]
    return str(api_base) if api_base else None


def _index_of(item: Any) -> int:
    if isinstance(item, dict):
        return int(item.get("index", 0) or 0)
    return int(getattr(item, "index", 0) or 0)


def _vector_of(item: Any) -> list[float]:
    raw = item.get("embedding", []) if isinstance(item, dict) else getattr(item, "embedding", [])
    return [float(value) for value in raw]


def _status_code(exc: Exception) -> int | None:
    code = getattr(exc, "status_code", None)
    if isinstance(code, int):
        return code
    response = getattr(exc, "response", None)
    code = getattr(response, "status_code", None)
    return code if isinstance(code, int) else None


def _is_retryable(exc: Exception) -> bool:
    """Whether another attempt may succeed."""
    code = _status_code(exc)
    if code is not None:
        return code == 429 or 500 <= code < 600
    name = type(exc).__name__
    return any(marker in name for marker in _RETRYABLE_NAMES)
