"""Phase 5b and 5c: the real embedder.

No test reaches a provider: the embedder is given a fake client that records
what it was asked to embed.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from pathlib import Path
from typing import Any, ClassVar

import pytest

from oracle_hcm.config.models import EmbeddingSpec, ModelRegistry, load_model_registry
from oracle_hcm.config.providers import Provider
from oracle_hcm.config.settings import Settings
from oracle_hcm.errors import (
    ConfigurationError,
    LLMCallError,
    MissingApiKeyError,
    ModelNotConfiguredError,
)
from oracle_hcm.knowledge.embeddings import DeterministicEmbedder
from oracle_hcm.knowledge.litellm_embedding import (
    EMBEDDING_DIMENSIONS,
    EmbeddingResponse,
    LiteLLMEmbedder,
    LiteLLMEmbeddingBackend,
    OpenAIEmbedder,
    _is_retryable,
    build_embedder,
    effective_provider,
    estimate_tokens,
)
from oracle_hcm.knowledge.vectors import (
    COLLECTION_RECREATED_ACTION,
    MemoryRecord,
    VectorStore,
    qdrant_client,
)
from oracle_hcm.llm.limits import RateLimiter
from oracle_hcm.log.eventlog import EventLog

TEST_COLLECTION = "test_embedding_index"
CONFIGURED_COLLECTION = "test_embedding_configured"

SECRET = "sk-abcdefghijklmnopqrstuvwx"
PERSONAL = "ada.lovelace@example.com"


class FakeEmbeddingClient:
    """An embedding service that never leaves the process."""

    def __init__(self) -> None:
        self.calls: list[list[str]] = []
        self.models: list[str] = []
        self.api_keys: list[str] = []
        self.failures: list[Exception] = []

    def __call__(
        self, *, model: str, inputs: list[str], api_key: str, dimensions: int
    ) -> EmbeddingResponse:
        self.calls.append(list(inputs))
        self.models.append(model)
        self.api_keys.append(api_key)
        if self.failures:
            raise self.failures.pop(0)
        vectors = [
            [float((index + position) % 7) / 7.0 for position in range(dimensions)]
            for index, _text in enumerate(inputs)
        ]
        return EmbeddingResponse(vectors=vectors, total_tokens=sum(len(text) for text in inputs))

    @property
    def texts(self) -> list[str]:
        """Every text the client was given."""
        return [text for call in self.calls for text in call]


class RateLimitError(Exception):
    """A failure that is worth another attempt."""

    status_code = 429


class ServerError(Exception):
    """A failure of the service that is worth another attempt."""

    status_code = 503


class UnauthorizedError(Exception):
    """A failure that another attempt cannot fix."""

    status_code = 401


@pytest.fixture
def client() -> FakeEmbeddingClient:
    return FakeEmbeddingClient()


@pytest.fixture
def slept() -> list[float]:
    return []


@pytest.fixture
def settings() -> Settings:
    return Settings.from_env({"OPENAI_API_KEY": "openai-test-key"})


@pytest.fixture
def embedder(
    client: FakeEmbeddingClient, settings: Settings, slept: list[float]
) -> OpenAIEmbedder:
    """An embedder with a fake client and a sleep that only records."""
    return OpenAIEmbedder(
        settings=settings,
        backend=client,
        sleep=slept.append,
        batch_size=2,
    )


def qdrant_is_ready() -> bool:
    """Whether the Qdrant container answers."""
    try:
        qdrant_client().get_collections()
    except Exception:
        return False
    return True


@pytest.fixture
def store() -> Iterator[VectorStore]:
    """A vector store on the live container, with its own collection."""
    if not qdrant_is_ready():
        pytest.skip("the qdrant container does not answer")
    vector_store = VectorStore(
        qdrant_client(),
        DeterministicEmbedder(),
        collections=(TEST_COLLECTION,),
    )
    vector_store.drop_collections()
    vector_store.ensure_collections()
    yield vector_store
    vector_store.drop_collections()


@pytest.fixture
def configured_store() -> Iterator[VectorStore]:
    """A vector store whose embedder has the dimension of the configuration."""
    if not qdrant_is_ready():
        pytest.skip("the qdrant container does not answer")
    embedder = LiteLLMEmbedder(
        model="openai/text-embedding-3-small",
        dimensions=1536,
        provider=Provider.OPENAI,
        settings=Settings.from_env({"OPENAI_API_KEY": "openai-test-key"}),
        backend=FakeEmbeddingClient(),
    )
    vector_store = VectorStore(qdrant_client(), embedder, collections=(CONFIGURED_COLLECTION,))
    vector_store.drop_collections()
    vector_store.ensure_collections()
    yield vector_store
    vector_store.drop_collections()


# --- the embedder --------------------------------------------------------


def test_the_embedder_sends_the_texts_in_batches(
    embedder: OpenAIEmbedder, client: FakeEmbeddingClient
) -> None:
    vectors = embedder.embed(["one", "two", "three", "four", "five"])

    assert len(vectors) == 5
    assert [len(call) for call in client.calls] == [2, 2, 1]


def test_the_embedder_asks_for_the_vectors_of_its_own_size(
    embedder: OpenAIEmbedder, client: FakeEmbeddingClient
) -> None:
    embedder.embed(["one"])

    assert client.models == ["text-embedding-3-small"]
    assert embedder.dimensions == EMBEDDING_DIMENSIONS
    assert len(embedder.embed(["one"])[0]) == EMBEDDING_DIMENSIONS


def test_the_embedder_redacts_the_secrets_and_the_personal_data(
    embedder: OpenAIEmbedder, client: FakeEmbeddingClient
) -> None:
    embedder.embed([f"the operator {PERSONAL} holds the key {SECRET}"])

    assert client.texts
    assert SECRET not in client.texts[0]
    assert PERSONAL not in client.texts[0]
    assert "[REDACTED]" in client.texts[0]


def test_the_embedder_caps_the_length_of_a_text(
    client: FakeEmbeddingClient, settings: Settings
) -> None:
    embedder = OpenAIEmbedder(settings=settings, backend=client)

    embedder.embed(["x" * 20_000])

    assert len(client.texts[0]) == 8_000


def test_the_embedder_needs_no_key_until_it_is_called() -> None:
    embedder = OpenAIEmbedder(settings=Settings.from_env({}))

    with pytest.raises(MissingApiKeyError):
        embedder.embed(["one"])


def test_the_embedder_reads_the_key_of_the_environment(
    monkeypatch: pytest.MonkeyPatch, client: FakeEmbeddingClient
) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "openai-env-key")
    embedder = OpenAIEmbedder(backend=client, sleep=lambda _seconds: None)

    embedder.embed(["one"])

    assert client.api_keys == ["openai-env-key"]


def test_the_embedder_waits_when_the_rate_is_exceeded(
    client: FakeEmbeddingClient, settings: Settings, slept: list[float]
) -> None:
    embedder = OpenAIEmbedder(
        settings=settings,
        backend=client,
        limiter=RateLimiter(window_seconds=60.0),
        rpm=1,
        tpm=0,
        sleep=slept.append,
    )

    embedder.embed(["one"])
    embedder.embed(["two"])

    assert len(client.calls) == 2
    assert slept and slept[0] > 0


def test_the_embedder_waits_when_the_token_budget_is_used(
    client: FakeEmbeddingClient, settings: Settings, slept: list[float]
) -> None:
    embedder = OpenAIEmbedder(
        settings=settings,
        backend=client,
        limiter=RateLimiter(window_seconds=60.0),
        rpm=0,
        tpm=1,
        sleep=slept.append,
    )

    embedder.embed(["one"])
    embedder.embed(["two"])

    assert len(client.calls) == 2
    assert slept and slept[0] > 0


def test_the_embedder_retries_a_rate_limit_with_a_backoff(
    client: FakeEmbeddingClient, settings: Settings, slept: list[float]
) -> None:
    client.failures = [RateLimitError("too many requests"), RateLimitError("too many requests")]
    embedder = OpenAIEmbedder(
        settings=settings,
        backend=client,
        sleep=slept.append,
        backoff_base=0.5,
    )

    vectors = embedder.embed(["one"])

    assert len(vectors) == 1
    assert len(client.calls) == 3
    assert slept == [0.5, 1.0]


def test_the_embedder_retries_a_failure_of_the_service(
    client: FakeEmbeddingClient, settings: Settings, slept: list[float]
) -> None:
    client.failures = [ServerError("the service is down")]
    embedder = OpenAIEmbedder(settings=settings, backend=client, sleep=slept.append)

    assert len(embedder.embed(["one"])) == 1
    assert len(client.calls) == 2


def test_the_embedder_gives_up_after_the_last_attempt(
    client: FakeEmbeddingClient, settings: Settings, slept: list[float]
) -> None:
    client.failures = [ServerError("the service is down")] * 4
    embedder = OpenAIEmbedder(settings=settings, backend=client, sleep=slept.append)

    with pytest.raises(LLMCallError):
        embedder.embed(["one"])

    assert len(client.calls) == 4


def test_the_embedder_does_not_retry_a_failure_that_cannot_change(
    client: FakeEmbeddingClient, settings: Settings, slept: list[float]
) -> None:
    client.failures = [UnauthorizedError("the key is wrong")]
    embedder = OpenAIEmbedder(settings=settings, backend=client, sleep=slept.append)

    with pytest.raises(LLMCallError):
        embedder.embed(["one"])

    assert len(client.calls) == 1
    assert slept == []


def test_the_embedder_refuses_a_vector_of_the_wrong_size(
    settings: Settings, slept: list[float]
) -> None:
    class WrongSize(FakeEmbeddingClient):
        def __call__(
            self, *, model: str, inputs: list[str], api_key: str, dimensions: int
        ) -> EmbeddingResponse:
            return EmbeddingResponse(vectors=[[0.1, 0.2]])

    embedder = OpenAIEmbedder(
        settings=settings, backend=WrongSize(), sleep=slept.append
    )

    with pytest.raises(LLMCallError):
        embedder.embed(["one"])


def test_the_embedder_names_itself_after_its_model() -> None:
    assert OpenAIEmbedder().name == "openai/text-embedding-3-small"
    assert OpenAIEmbedder(model="openai/text-embedding-3-large").name == (
        "openai/text-embedding-3-large"
    )


def test_the_embedder_returns_nothing_for_no_text(settings: Settings) -> None:
    assert OpenAIEmbedder(settings=settings).embed([]) == []


# --- the collections ------------------------------------------------------


def test_the_collection_names_the_embedder_that_owns_it(store: VectorStore) -> None:
    info = qdrant_client().get_collection(TEST_COLLECTION)

    assert info.config.metadata is not None
    assert info.config.metadata["embedder"] == "deterministic"
    assert info.config.params.vectors is not None
    assert info.config.params.vectors.size == 64


def test_a_collection_of_another_embedder_is_refused(store: VectorStore) -> None:
    class Other(DeterministicEmbedder):
        @property
        def name(self) -> str:
            return "openai/text-embedding-3-small"

    other = VectorStore(qdrant_client(), Other(), collections=(TEST_COLLECTION,))

    with pytest.raises(ConfigurationError):
        other.ensure_collections()


def test_a_collection_of_the_wrong_size_is_recreated(tmp_path: Path) -> None:
    if not qdrant_is_ready():
        pytest.skip("the qdrant container does not answer")
    event_log = EventLog(tmp_path / "audit.jsonl")
    store = VectorStore(
        qdrant_client(),
        DeterministicEmbedder(),
        collections=(TEST_COLLECTION,),
        event_log=event_log,
    )
    store.drop_collections()
    store.ensure_collections()
    record = MemoryRecord(
        tenant_id="tenant-a",
        artifact_hash="hash-1",
        text="the attendance module",
        content_key="pkg/attendance.py",
    )
    store.upsert(TEST_COLLECTION, [record])

    class Bigger(DeterministicEmbedder):
        def __init__(self) -> None:
            super().__init__(dimensions=128)

    bigger = VectorStore(
        qdrant_client(),
        Bigger(),
        collections=(TEST_COLLECTION,),
        event_log=event_log,
    )
    bigger.ensure_collections()

    info = qdrant_client().get_collection(TEST_COLLECTION)
    assert info.config.params.vectors is not None
    assert info.config.params.vectors.size == 128
    assert bigger.count(TEST_COLLECTION, tenant_id="tenant-a") == 0
    events = [
        event for event in event_log.read_all() if event.action == COLLECTION_RECREATED_ACTION
    ]
    assert len(events) == 1
    assert events[0].payload["collection"] == TEST_COLLECTION
    assert events[0].payload["old_vector_size"] == 64
    assert events[0].payload["new_vector_size"] == 128
    assert events[0].payload["dropped_points"] == 1
    store.drop_collections()


def test_a_collection_without_a_name_is_recreated_when_the_size_differs(
    tmp_path: Path,
) -> None:
    if not qdrant_is_ready():
        pytest.skip("the qdrant container does not answer")
    from qdrant_client import models

    client = qdrant_client()
    store = VectorStore(client, DeterministicEmbedder(), collections=(TEST_COLLECTION,))
    store.drop_collections()
    client.create_collection(
        collection_name=TEST_COLLECTION,
        vectors_config=models.VectorParams(size=64, distance=models.Distance.COSINE),
    )

    class Bigger(DeterministicEmbedder):
        def __init__(self) -> None:
            super().__init__(dimensions=128)

    event_log = EventLog(tmp_path / "audit.jsonl")
    bigger = VectorStore(
        client, Bigger(), collections=(TEST_COLLECTION,), event_log=event_log
    )
    bigger.ensure_collections()

    info = client.get_collection(TEST_COLLECTION)
    assert info.config.params.vectors is not None
    assert info.config.params.vectors.size == 128
    assert info.config.metadata is not None
    assert info.config.metadata["embedder"] == "deterministic"
    events = [
        event for event in event_log.read_all() if event.action == COLLECTION_RECREATED_ACTION
    ]
    assert len(events) == 1
    store.drop_collections()


def test_a_collection_without_a_name_is_adopted_when_the_size_is_the_same(
    tmp_path: Path,
) -> None:
    if not qdrant_is_ready():
        pytest.skip("the qdrant container does not answer")
    from qdrant_client import models

    client = qdrant_client()
    store = VectorStore(client, DeterministicEmbedder(), collections=(TEST_COLLECTION,))
    store.drop_collections()
    client.create_collection(
        collection_name=TEST_COLLECTION,
        vectors_config=models.VectorParams(size=64, distance=models.Distance.COSINE),
    )
    record = MemoryRecord(
        tenant_id="tenant-a",
        artifact_hash="hash-1",
        text="the attendance module",
        content_key="pkg/attendance.py",
    )
    store.upsert(TEST_COLLECTION, [record])

    store.ensure_collections()

    info = client.get_collection(TEST_COLLECTION)
    assert info.config.metadata is not None
    assert info.config.metadata["embedder"] == "deterministic"
    assert store.count(TEST_COLLECTION, tenant_id="tenant-a") == 1
    store.drop_collections()


def test_default_collections_recreated_when_vector_size_differs(tmp_path: Path) -> None:
    """repo_index and episodic_memory are recreated when vector size changes."""
    if not qdrant_is_ready():
        pytest.skip("the qdrant container does not answer")
    from oracle_hcm.knowledge.vectors import DEFAULT_COLLECTIONS, REPO_INDEX
    client = qdrant_client()
    event_log = EventLog(tmp_path / "audit.jsonl")

    # Start with a 64-dim deterministic collection
    store64 = VectorStore(
        client,
        DeterministicEmbedder(dimensions=64),
        collections=DEFAULT_COLLECTIONS,
        event_log=event_log,
    )
    store64.ensure_collections()

    class ConfiguredEmbedder(DeterministicEmbedder):
        def __init__(self) -> None:
            super().__init__(dimensions=768)

        @property
        def name(self) -> str:
            return "gemini/gemini-embedding-2"

    store768 = VectorStore(
        client,
        ConfiguredEmbedder(),
        collections=DEFAULT_COLLECTIONS,
        event_log=event_log,
    )
    store768.ensure_collections()

    info = client.get_collection(REPO_INDEX)
    assert info.config.params.vectors is not None
    assert info.config.params.vectors.size == 768
    events = [
        e for e in event_log.read_all() if e.action == COLLECTION_RECREATED_ACTION
    ]
    assert len(events) >= 1
    assert any(e.payload["collection"] == REPO_INDEX for e in events)


def test_the_size_of_the_collection_comes_from_the_embedder() -> None:
    store = VectorStore(
        qdrant_client(),
        DeterministicEmbedder(dimensions=32),
        collections=(TEST_COLLECTION,),
    )

    assert store.vector_size == 32
    assert store.embedder_name == "deterministic"


def test_writing_the_same_artifact_twice_leaves_one_point(
    store: VectorStore, embedder: OpenAIEmbedder
) -> None:
    record = MemoryRecord(
        tenant_id="tenant-a",
        artifact_hash="hash-1",
        text="the attendance module",
        content_key="pkg/attendance.py",
    )
    first = store.upsert(TEST_COLLECTION, [record])
    second = store.upsert(TEST_COLLECTION, [record])

    assert first == second
    assert store.count(TEST_COLLECTION, tenant_id="tenant-a") == 1


def test_the_engine_keeps_the_deterministic_embedder_as_its_default() -> None:
    from oracle_hcm.app import AppConfig

    assert AppConfig().embedder is None
    assert DeterministicEmbedder().name == "deterministic"


def test_the_cli_can_choose_the_embedder() -> None:
    from oracle_hcm.__main__ import _embedder

    assert isinstance(_embedder("deterministic"), DeterministicEmbedder)
    assert isinstance(_embedder("openai"), OpenAIEmbedder)


def test_the_live_check_script_prints_only_the_length_and_the_latency() -> None:
    script = Path(__file__).resolve().parents[1] / "scripts" / "check_embedding.py"
    source = script.read_text(encoding="utf-8")

    labels = set(re.findall(r'print\(f?"([a-z_]+):', source))
    assert labels == {"vector_length", "latency_ms"}
    assert "api_key" not in source
    assert "OPENAI_API_KEY" not in source


def test_the_deterministic_embedder_names_itself() -> None:
    embedder = DeterministicEmbedder()

    assert embedder.name == "deterministic"
    assert embedder.dimensions == 64


def test_the_deterministic_embedder_redacts_before_it_hashes() -> None:
    embedder = DeterministicEmbedder()

    first = embedder.embed([f"the operator {PERSONAL} holds the key {SECRET}"])
    second = embedder.embed(["the operator [REDACTED] holds the key [REDACTED]"])

    assert first == second


def test_the_openai_embedder_is_an_embedder(settings: Settings) -> None:
    from oracle_hcm.knowledge.embeddings import Embedder

    embedder: Embedder = OpenAIEmbedder(settings=settings)

    assert embedder.name == "openai/text-embedding-3-small"
    assert embedder.dimensions == EMBEDDING_DIMENSIONS


def test_the_backend_of_the_embedder_is_replaceable(settings: Settings) -> None:
    client = FakeEmbeddingClient()
    embedder = OpenAIEmbedder(settings=settings, backend=client)

    embedder.embed(["one"])

    assert client.calls == [["one"]]


def test_the_response_of_the_service_is_read(settings: Settings) -> None:
    class Service:
        def __call__(
            self, *, model: str, inputs: list[str], api_key: str, dimensions: int
        ) -> Any:
            return EmbeddingResponse(
                vectors=[[0.5] * dimensions],
                total_tokens=42,
            )

    embedder = OpenAIEmbedder(settings=settings, backend=Service())

    vectors = embedder.embed(["one"])

    assert len(vectors[0]) == EMBEDDING_DIMENSIONS


def test_the_litellm_backend_reads_the_answer_of_the_service(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import litellm

    class Usage:
        total_tokens = 11

    class Response:
        data: ClassVar[list[dict[str, Any]]] = [
            {"index": 1, "embedding": [0.3, 0.4]},
            {"index": 0, "embedding": [0.1, 0.2]},
        ]
        usage = Usage()

    seen: dict[str, Any] = {}

    def fake_embedding(**kwargs: Any) -> Response:
        seen.update(kwargs)
        return Response()

    monkeypatch.setattr(litellm, "embedding", fake_embedding)
    backend = LiteLLMEmbeddingBackend()

    response = backend(
        model="text-embedding-3-small",
        inputs=["one", "two"],
        api_key="openai-test-key",
        dimensions=2,
    )

    assert response.vectors == [[0.1, 0.2], [0.3, 0.4]]
    assert response.total_tokens == 11
    assert seen["model"] == "text-embedding-3-small"
    assert seen["input"] == ["one", "two"]
    assert seen["dimensions"] == 2


def test_the_tokens_of_a_batch_are_estimated() -> None:
    assert estimate_tokens(["a" * 40]) == 10
    assert estimate_tokens(["a", ""]) == 2


def test_only_a_transient_failure_is_retried() -> None:
    assert _is_retryable(RateLimitError("too many")) is True
    assert _is_retryable(ServerError("down")) is True
    assert _is_retryable(UnauthorizedError("wrong")) is False
    assert _is_retryable(ValueError("wrong shape")) is False


# --- the configured embedder ---------------------------------------------


def test_the_embedder_takes_its_model_and_its_size_from_the_configuration(
    client: FakeEmbeddingClient,
) -> None:
    spec = EmbeddingSpec(
        model="gemini/text-embedding-004",
        provider=Provider.GEMINI,
        dimensions=768,
        rpm=7,
        tpm=1234,
    )
    embedder = build_embedder(
        spec, settings=Settings.from_env({"GEMINI_API_KEY": "gemini-test-key"}), backend=client
    )

    vectors = embedder.embed(["one"])

    assert client.models == ["gemini/text-embedding-004"]
    assert embedder.dimensions == 768
    assert embedder.name == "gemini/text-embedding-004"
    assert len(vectors[0]) == 768


def test_the_embedder_holds_itself_to_the_limits_of_the_configuration(
    client: FakeEmbeddingClient, settings: Settings, slept: list[float]
) -> None:
    spec = EmbeddingSpec(model="openai/text-embedding-3-small", dimensions=8, rpm=1, tpm=0)
    embedder = build_embedder(
        spec,
        settings=settings,
        backend=client,
        limiter=RateLimiter(window_seconds=60.0),
        sleep=slept.append,
    )

    embedder.embed(["one"])
    embedder.embed(["two"])

    assert len(client.calls) == 2
    assert slept and slept[0] > 0


def test_a_placeholder_embedding_model_is_never_called(
    client: FakeEmbeddingClient, settings: Settings
) -> None:
    spec = EmbeddingSpec(model="REPLACE_WITH_EMBEDDING_MODEL_ID", provider=Provider.OPENAI)
    embedder = build_embedder(spec, settings=settings, backend=client)

    with pytest.raises(ModelNotConfiguredError):
        embedder.embed(["one"])

    assert client.calls == []


def test_the_embedder_asks_for_the_key_of_its_own_provider(
    client: FakeEmbeddingClient,
) -> None:
    spec = EmbeddingSpec(model="gemini/text-embedding-004", provider=Provider.GEMINI)
    embedder = build_embedder(spec, settings=Settings.from_env({}), backend=client)

    with pytest.raises(MissingApiKeyError):
        embedder.embed(["one"])

    assert client.calls == []


def test_the_provider_of_the_model_id_wins_over_the_configured_one(
    client: FakeEmbeddingClient,
) -> None:
    spec = EmbeddingSpec(model="groq/text-embedding-3-small", provider=Provider.OPENAI)
    embedder = build_embedder(
        spec, settings=Settings.from_env({"GROQ_API_KEY": "groq-test-key"}), backend=client
    )

    embedder.embed(["one"])

    assert embedder.provider is Provider.GROQ
    assert client.api_keys == ["groq-test-key"]


def test_a_bare_model_id_uses_the_configured_provider(
    client: FakeEmbeddingClient,
) -> None:
    spec = EmbeddingSpec(model="text-embedding-3-small", provider=Provider.OPENAI)
    embedder = build_embedder(
        spec, settings=Settings.from_env({"OPENAI_API_KEY": "openai-test-key"}), backend=client
    )

    embedder.embed(["one"])

    assert embedder.provider is Provider.OPENAI
    assert embedder.name == "openai/text-embedding-3-small"
    assert client.api_keys == ["openai-test-key"]


def test_a_model_without_a_provider_cannot_be_served(
    client: FakeEmbeddingClient, settings: Settings
) -> None:
    embedder = LiteLLMEmbedder(model="mystery-embedding", settings=settings, backend=client)

    with pytest.raises(ConfigurationError):
        embedder.embed(["one"])


def test_the_provider_of_a_model_is_resolved_once() -> None:
    assert effective_provider("openai/text-embedding-3-small", Provider.UNKNOWN) is (
        Provider.OPENAI
    )
    assert effective_provider("text-embedding-3-small", Provider.GEMINI) is Provider.GEMINI
    assert effective_provider("mystery-model", Provider.UNKNOWN) is Provider.UNKNOWN


def test_the_size_of_the_collection_comes_from_the_configured_dimension(
    client: FakeEmbeddingClient, settings: Settings
) -> None:
    spec = EmbeddingSpec(model="openai/text-embedding-3-small", dimensions=24)
    embedder = build_embedder(spec, settings=settings, backend=client)

    store = VectorStore(qdrant_client(), embedder, collections=(TEST_COLLECTION,))

    assert store.vector_size == 24
    assert store.embedder_name == "openai/text-embedding-3-small"


def test_the_collection_is_built_with_the_configured_dimension(
    configured_store: VectorStore,
) -> None:
    info = qdrant_client().get_collection(CONFIGURED_COLLECTION)

    assert info.config.params.vectors is not None
    assert info.config.params.vectors.size == 1536
    assert info.config.metadata is not None
    assert info.config.metadata["embedder"] == "openai/text-embedding-3-small"


def test_the_collection_of_the_configured_dimension_refuses_another_embedder(
    configured_store: VectorStore,
) -> None:
    other = VectorStore(
        qdrant_client(), DeterministicEmbedder(), collections=(CONFIGURED_COLLECTION,)
    )

    with pytest.raises(ConfigurationError):
        other.ensure_collections()


def test_the_shipped_configuration_names_the_embedding_model(project_root: Path) -> None:
    registry = load_model_registry(project_root / "config" / "models.yaml")

    spec = registry.require_embeddings()

    assert spec.model == "gemini/gemini-embedding-2"
    assert spec.is_configured is True
    assert spec.dimensions == 768
    assert spec.rpm == 100
    assert spec.tpm == 30000


def test_the_engine_keeps_the_deterministic_embedder_for_the_offline_runs() -> None:
    from oracle_hcm.app import AppConfig, _default_embedder

    registry = load_model_registry()
    offline = _default_embedder(registry, AppConfig(use_fake_backend=True), Settings.from_env({}))

    assert isinstance(offline, DeterministicEmbedder)


def test_a_live_run_uses_the_configured_embedder() -> None:
    from oracle_hcm.app import AppConfig, _default_embedder

    registry = load_model_registry()
    live = _default_embedder(registry, AppConfig(use_fake_backend=False), Settings.from_env({}))

    assert isinstance(live, LiteLLMEmbedder)
    assert live.dimensions == 768


def test_the_cli_offers_the_configured_embedder() -> None:
    from oracle_hcm.__main__ import _embedder

    assert _embedder("auto") is None
    assert isinstance(_embedder("deterministic"), DeterministicEmbedder)
    assert isinstance(_embedder("openai"), OpenAIEmbedder)
    assert isinstance(_embedder("configured"), LiteLLMEmbedder)


def test_the_registry_without_an_embedding_model_says_so() -> None:
    registry = ModelRegistry(roles={})

    with pytest.raises(ConfigurationError):
        registry.require_embeddings()
