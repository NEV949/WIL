"""The vector store.

Two collections live in Qdrant: ``repo_index`` holds what the engine knows
about the code of an artifact, ``episodic_memory`` holds what a successful
deployment learned. Every point carries the tenant that owns it, the agent
that wrote it, the task type and the hash of the artifact it belongs to.

The id of a point is derived from the hash of the artifact, so writing the
same artifact again replaces the point instead of duplicating it. Every
query carries a tenant filter: a tenant never reads the points of another
tenant, and there is no way to ask for a query without one.

A collection belongs to one embedder. The name of the embedder and the size
of its vectors are written in the metadata of the collection: a collection
that holds the vectors of another embedder is refused, and a collection whose
vectors are of the wrong size is recreated and the recreation is written to
the audit log. Vectors of two embedders are never mixed in one collection.
"""

from __future__ import annotations

import logging
import uuid
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any

from oracle_hcm.canonical import sha256_hex
from oracle_hcm.errors import ConfigurationError
from oracle_hcm.knowledge.embeddings import Embedder
from oracle_hcm.log.eventlog import EventLog

__all__ = [
    "COLLECTION_RECREATED_ACTION",
    "DEFAULT_COLLECTIONS",
    "DEFAULT_QDRANT_URL",
    "EPISODIC_MEMORY",
    "REPO_INDEX",
    "MemoryRecord",
    "RetrievedPoint",
    "VectorStore",
    "point_id",
    "qdrant_client",
]

_LOGGER = logging.getLogger(__name__)

REPO_INDEX = "repo_index"
EPISODIC_MEMORY = "episodic_memory"

DEFAULT_COLLECTIONS: tuple[str, ...] = (REPO_INDEX, EPISODIC_MEMORY)

DEFAULT_QDRANT_URL = "http://127.0.0.1:6333"

COLLECTION_RECREATED_ACTION = "qdrant_collection_recreated"
"""The audit action of a collection that was recreated."""

SYSTEM_TENANT = "system"
"""The tenant of the events that belong to the engine itself."""

_ID_NAMESPACE = uuid.UUID("6f6b2f36-3f6a-5a4b-9a3e-2d1c0b8a7f60")


def qdrant_client(url: str = DEFAULT_QDRANT_URL) -> Any:
    """The client of the Qdrant container.

    The environment of the host carries a NO_PROXY list with an IPv6 entry
    that the http client cannot parse, so the client is told to ignore the
    proxy settings of the environment: it only ever talks to the local
    container anyway.
    """
    from qdrant_client import QdrantClient

    return QdrantClient(url=url, trust_env=False, check_compatibility=False)


def point_id(collection: str, artifact_hash: str, content_key: str = "") -> str:
    """The id of a point, derived from the hash of the artifact."""
    seed = f"{collection}|{artifact_hash}|{content_key}"
    return str(uuid.uuid5(_ID_NAMESPACE, seed))


@dataclass(frozen=True)
class MemoryRecord:
    """One point of the store."""

    tenant_id: str
    artifact_hash: str
    text: str
    agent: str = "orchestrator"
    task_type: str = "feature"
    kind: str = "summary"
    source: str = ""
    run_id: str = ""
    content_key: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    def payload(self) -> dict[str, Any]:
        """The payload of the point."""
        payload: dict[str, Any] = {
            "tenant_id": self.tenant_id,
            "agent": self.agent,
            "task_type": self.task_type,
            "artifact_hash": self.artifact_hash,
            "kind": self.kind,
            "source": self.source,
            "run_id": self.run_id,
            "content_hash": sha256_hex(self.text.encode("utf-8")),
            "text": self.text,
        }
        payload.update(self.metadata)
        return payload


@dataclass(frozen=True)
class RetrievedPoint:
    """One point that came back from a query."""

    id: str
    score: float
    payload: dict[str, Any]

    @property
    def text(self) -> str:
        return str(self.payload.get("text", ""))


class VectorStore:
    """The Qdrant collections of the engine."""

    def __init__(
        self,
        client: Any,
        embedder: Embedder,
        *,
        collections: Sequence[str] = DEFAULT_COLLECTIONS,
        event_log: EventLog | None = None,
        audit_tenant_id: str = SYSTEM_TENANT,
    ) -> None:
        self._client = client
        self._embedder = embedder
        self._collections = tuple(collections)
        self._vector_size = embedder.dimensions
        self._embedder_name = embedder.name
        self._event_log = event_log
        self._audit_tenant_id = audit_tenant_id

    @property
    def collections(self) -> tuple[str, ...]:
        """The names of the collections."""
        return self._collections

    @property
    def embedder_name(self) -> str:
        """The name of the embedder that owns the vectors."""
        return self._embedder_name

    @property
    def vector_size(self) -> int:
        """The length of the vectors of the embedder."""
        return self._vector_size

    def ensure_collections(self) -> None:
        """Create the collections when they do not exist yet.

        A collection that holds the vectors of another embedder is refused. A
        collection whose vectors are of the wrong size is recreated, and the
        recreation is written to the audit log.
        """
        for name in self._collections:
            self._ensure_collection(name)

    def _ensure_collection(self, name: str) -> None:
        existing = {item.name for item in self._client.get_collections().collections}
        if name not in existing:
            self._create_collection(name)
            return
        info = self._client.get_collection(name)
        metadata = _collection_metadata(info)
        stored_name = str(metadata.get("embedder", ""))
        stored_size = _collection_size(info)
        if name in DEFAULT_COLLECTIONS:
            if stored_size is not None and stored_size != self._vector_size:
                self._recreate_collection(name, stored_size)
                return
            if stored_name and stored_name != self._embedder_name:
                self._recreate_collection(name, stored_size)
                return
        else:
            if stored_name and stored_name != self._embedder_name:
                raise ConfigurationError(
                    f"the collection '{name}' holds the vectors of the embedder "
                    f"'{stored_name}' and cannot hold the vectors of "
                    f"'{self._embedder_name}': drop the collection or migrate it "
                    f"before the embedder changes"
                )
            if stored_size is not None and stored_size != self._vector_size:
                self._recreate_collection(name, stored_size)
                return
        if not stored_name:
            self._client.update_collection(
                collection_name=name,
                metadata={"embedder": self._embedder_name, "vector_size": self._vector_size},
            )

    def _create_collection(self, name: str) -> None:
        from qdrant_client import models

        self._client.create_collection(
            collection_name=name,
            vectors_config=models.VectorParams(
                size=self._vector_size,
                distance=models.Distance.COSINE,
            ),
            metadata={"embedder": self._embedder_name, "vector_size": self._vector_size},
        )

    def _recreate_collection(self, name: str, old_size: int | None) -> None:
        """Replace a collection whose vectors are of the wrong size."""
        dropped = int(self._client.count(collection_name=name, exact=True).count)
        self._client.delete_collection(collection_name=name)
        self._create_collection(name)
        _LOGGER.warning(
            "the collection '%s' was recreated: the vectors of %s dimensions do not "
            "fit the embedder '%s' of %s dimensions",
            name,
            old_size,
            self._embedder_name,
            self._vector_size,
        )
        if self._event_log is None:
            return
        self._event_log.append(
            tenant_id=self._audit_tenant_id,
            actor="orchestrator",
            action=COLLECTION_RECREATED_ACTION,
            payload={
                "event_type": "QdrantCollectionRecreated",
                "collection": name,
                "embedder": self._embedder_name,
                "old_vector_size": old_size,
                "new_vector_size": self._vector_size,
                "dropped_points": dropped,
            },
        )

    def drop_collections(self) -> None:
        """Remove the collections, used by the tests."""
        existing = {item.name for item in self._client.get_collections().collections}
        for name in self._collections:
            if name not in existing:
                continue
            self._client.delete_collection(collection_name=name)

    def upsert(self, collection: str, records: Sequence[MemoryRecord]) -> list[str]:
        """Write the records and return the ids of the points.

        The id of a point comes from the hash of the artifact, so writing the
        same record twice leaves a single point behind.
        """
        from qdrant_client import models

        if not records:
            return []
        vectors = self._embedder.embed([record.text for record in records])
        points = [
            models.PointStruct(
                id=point_id(collection, record.artifact_hash, record.content_key),
                vector=vector,
                payload=record.payload(),
            )
            for record, vector in zip(records, vectors, strict=True)
        ]
        self._client.upsert(collection_name=collection, points=points)
        return [str(point.id) for point in points]

    def search(
        self,
        collection: str,
        query: str,
        *,
        tenant_id: str,
        top_k: int = 3,
    ) -> list[RetrievedPoint]:
        """The points of one tenant that match a query."""
        if not tenant_id:
            raise ValueError("a query must name its tenant")
        self._ensure_collection(collection)
        vector = self._embedder.embed([query])[0]
        response = self._client.query_points(
            collection_name=collection,
            query=vector,
            limit=top_k,
            query_filter=_tenant_filter(tenant_id),
            with_payload=True,
        )
        return [
            RetrievedPoint(
                id=str(hit.id),
                score=float(hit.score),
                payload=dict(hit.payload or {}),
            )
            for hit in response.points
        ]

    def count(self, collection: str, *, tenant_id: str) -> int:
        """How many points the tenant owns in a collection."""
        if not tenant_id:
            raise ValueError("a query must name its tenant")
        result = self._client.count(
            collection_name=collection,
            count_filter=_tenant_filter(tenant_id),
            exact=True,
        )
        return int(result.count)

    def delete_tenant(self, collection: str, *, tenant_id: str) -> None:
        """Remove every point of a tenant."""
        from qdrant_client import models

        self._client.delete(
            collection_name=collection,
            points_selector=models.FilterSelector(
                filter=_tenant_filter(tenant_id)
            ),
        )


def _collection_metadata(info: Any) -> dict[str, Any]:
    """The metadata of a collection, where the embedder is named."""
    config = getattr(info, "config", None)
    metadata = getattr(config, "metadata", None)
    return dict(metadata) if isinstance(metadata, dict) else {}


def _collection_size(info: Any) -> int | None:
    """The length of the vectors of a collection."""
    config = getattr(info, "config", None)
    params = getattr(config, "params", None)
    vectors = getattr(params, "vectors", None)
    if vectors is None:
        return None
    size = getattr(vectors, "size", None)
    if isinstance(size, int):
        return size
    if isinstance(vectors, dict):
        for value in vectors.values():
            candidate = getattr(value, "size", None)
            if isinstance(candidate, int):
                return candidate
    return None


def _tenant_filter(tenant_id: str) -> Any:
    """The filter that restricts a query to one tenant."""
    from qdrant_client import models

    return models.Filter(
        must=[
            models.FieldCondition(
                key="tenant_id",
                match=models.MatchValue(value=tenant_id),
            )
        ]
    )
