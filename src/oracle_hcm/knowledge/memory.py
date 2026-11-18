"""What a successful deployment teaches the engine.

Only an artifact that was verified and signed may teach the engine something.
The writer stores a short summary of the run in the episodic memory, indexes
the code of the artifact in the repository index, rebuilds the repository
graph and writes the whole write into the audit log.

A failed, refused or unsigned attempt never reaches the store: the writer
refuses it before it writes anything.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from oracle_hcm.canonical import sha256_hex
from oracle_hcm.errors import SigningError
from oracle_hcm.knowledge.domain import DomainGraph, build_domain_graph, domain_graph_path
from oracle_hcm.knowledge.graph import build_repo_graph, graph_dir
from oracle_hcm.knowledge.retrieval import RetrievalService
from oracle_hcm.knowledge.vectors import (
    EPISODIC_MEMORY,
    REPO_INDEX,
    MemoryRecord,
    VectorStore,
)
from oracle_hcm.log.eventlog import EventLog
from oracle_hcm.paths import keys_dir
from oracle_hcm.redaction import scrub_text
from oracle_hcm.schemas.artifacts import RequirementSpec
from oracle_hcm.signing.keys import PUBLIC_KEY_NAME, load_public_key
from oracle_hcm.signing.manifest import SignedManifest, verify_signed_manifest
from oracle_hcm.signing.signer import Verifier

__all__ = [
    "AUDIT_ACTION",
    "DeploymentMemory",
    "MemoryWrite",
    "MemoryWriter",
]

AUDIT_ACTION = "qdrant_updated"
"""The audit action of a write into the vector store."""

SUMMARY_FIELD_LIMIT = 300
"""How many characters of a summary field are stored."""

CODE_EXCERPT_LIMIT = 2000
"""How many characters of a file reach the repository index."""


@dataclass(frozen=True)
class DeploymentMemory:
    """What one accepted deployment learned."""

    tenant_id: str
    run_id: str
    artifact_hash: str
    requirement_id: str = ""
    task_type: str = "feature"
    worked: str = ""
    failed: str = ""

    def summary(self) -> str:
        """The summary as it is stored."""
        return (
            f"Task type: {self.task_type}\n"
            f"What worked: {_limit(self.worked)}\n"
            f"What failed: {_limit(self.failed)}\n"
            f"Artifact hash: {self.artifact_hash}"
        )


@dataclass(frozen=True)
class MemoryWrite:
    """The outcome of one memory write."""

    memory_id: str
    repo_ids: tuple[str, ...] = ()
    episodic_ids: tuple[str, ...] = ()
    graph_path: str = ""
    graph_nodes: int = 0
    domain_path: str = ""
    content_hashes: dict[str, str] = field(default_factory=dict)


def _limit(text: str) -> str:
    """Trim a field of the summary."""
    return text.strip()[:SUMMARY_FIELD_LIMIT]


class MemoryWriter:
    """Writes what an accepted deployment learned into the store."""

    def __init__(
        self,
        *,
        store: VectorStore,
        event_log: EventLog,
        keys_directory: Path | None = None,
        retrieval: RetrievalService | None = None,
        repo_collection: str = REPO_INDEX,
        episodic_collection: str = EPISODIC_MEMORY,
    ) -> None:
        self._store = store
        self._event_log = event_log
        self._keys_directory = keys_directory
        self._retrieval = retrieval
        self._repo_collection = repo_collection
        self._episodic_collection = episodic_collection

    def _verifier(self) -> Verifier:
        """The verifier of the public key of the host."""
        directory = self._keys_directory if self._keys_directory is not None else keys_dir()
        path = directory / PUBLIC_KEY_NAME
        if not path.is_file():
            raise SigningError(f"the public key is missing: {path}")
        return Verifier(load_public_key(path))

    def record(
        self,
        *,
        signed: SignedManifest,
        memory: DeploymentMemory,
        workspace: Path,
        spec: RequirementSpec | None = None,
    ) -> MemoryWrite:
        """Store what the deployment learned.

        The write is refused when the artifact is not signed by this host or
        when the memory belongs to another artifact.
        """
        if not memory.artifact_hash:
            raise ValueError("the memory must name the artifact it belongs to")
        if signed.manifest.root_hash != memory.artifact_hash:
            raise ValueError("the memory belongs to another artifact")
        if not verify_signed_manifest(signed, self._verifier()):
            raise ValueError("the artifact is not signed by this host, nothing is stored")

        summary = scrub_text(memory.summary())
        summary_record = MemoryRecord(
            tenant_id=memory.tenant_id,
            artifact_hash=memory.artifact_hash,
            text=summary,
            agent="orchestrator",
            task_type=memory.task_type,
            kind="summary",
            source=memory.requirement_id,
            run_id=memory.run_id,
            content_key="deployment",
            metadata={"requirement_id": memory.requirement_id},
        )
        files = self._artifact_files(signed, workspace)
        repo_records = [
            MemoryRecord(
                tenant_id=memory.tenant_id,
                artifact_hash=memory.artifact_hash,
                text=scrub_text(f"{path}\n{content[:CODE_EXCERPT_LIMIT]}"),
                agent="orchestrator",
                task_type=memory.task_type,
                kind="code",
                source=path,
                run_id=memory.run_id,
                content_key=path,
            )
            for path, content in sorted(files.items())
        ]

        self._store.ensure_collections()
        episodic_ids = self._store.upsert(self._episodic_collection, [summary_record])
        repo_ids = self._store.upsert(self._repo_collection, repo_records)

        repo_graph = build_repo_graph(workspace, artifact_hash=memory.artifact_hash)
        graph_path = repo_graph.save(graph_dir() / "repo.json")
        domain_graph: DomainGraph | None = None
        domain_path = ""
        if spec is not None:
            domain_graph = build_domain_graph(spec, repo=repo_graph)
            saved = domain_graph.save(domain_graph_path())
            domain_path = str(saved)
        if self._retrieval is not None:
            self._retrieval.register_graphs(
                memory.tenant_id, repo=repo_graph, domain=domain_graph
            )

        content_hashes = {
            "summary": sha256_hex(summary.encode("utf-8")),
            **{path: sha256_hex(content.encode("utf-8")) for path, content in files.items()},
        }
        write = MemoryWrite(
            memory_id=episodic_ids[0] if episodic_ids else "",
            repo_ids=tuple(repo_ids),
            episodic_ids=tuple(episodic_ids),
            graph_path=str(graph_path),
            graph_nodes=len(repo_graph.graph.nodes),
            domain_path=domain_path,
            content_hashes=content_hashes,
        )
        self._event_log.append(
            tenant_id=memory.tenant_id,
            actor="orchestrator",
            action=AUDIT_ACTION,
            payload={
                "event_type": "QdrantUpdated",
                "run_id": memory.run_id,
                "artifact_hash": memory.artifact_hash,
                "requirement_id": memory.requirement_id,
                "point_ids": [*episodic_ids, *repo_ids],
                "content_hashes": content_hashes,
                "graph_path": write.graph_path,
                "graph_nodes": write.graph_nodes,
            },
        )
        return write

    def _artifact_files(self, signed: SignedManifest, workspace: Path) -> dict[str, str]:
        """The files of the artifact, as they are indexed."""
        files: dict[str, str] = {}
        for entry in signed.manifest.files:
            path = workspace / entry.path
            if not path.is_file():
                continue
            files[entry.path] = path.read_text(encoding="utf-8", errors="replace")
        return files
