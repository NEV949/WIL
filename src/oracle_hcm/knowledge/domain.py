"""The domain graph.

The domain graph holds the entities of a requirement and the relations between
them. The entities and the relations come from the :class:`RequirementSpec`;
the code that implements an entity is linked to it with a ``handles`` edge, so
that the graph answers both "what belongs together" and "where does it live
in the code".

The graph is stored as JSON next to the repository graph.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import networkx as nx

from oracle_hcm.knowledge.graph import RepoGraph, graph_dir
from oracle_hcm.schemas.artifacts import RequirementSpec

__all__ = [
    "DOMAIN_EDGE_KINDS",
    "DOMAIN_NODE_KINDS",
    "DomainGraph",
    "build_domain_graph",
    "domain_graph_path",
]

DOMAIN_NODE_KINDS: tuple[str, ...] = ("entity", "file")
DOMAIN_EDGE_KINDS: tuple[str, ...] = ("references", "belongs_to", "handles")

_RELATIONSHIP_KINDS: frozenset[str] = frozenset({"references", "belongs_to"})


def domain_graph_path() -> Path:
    """Where the domain graph lives."""
    return graph_dir() / "domain.json"


def _snake(name: str) -> str:
    """The snake_case form of a name."""
    text = re.sub(r"(?<!^)(?=[A-Z])", "_", name.replace("-", "_"))
    return re.sub(r"_+", "_", text).strip("_").lower()


@dataclass
class DomainGraph:
    """The entities of a requirement and the relations between them."""

    graph: nx.DiGraph[str] = field(default_factory=nx.DiGraph)
    requirement_id: str = ""

    def add_entity(
        self,
        name: str,
        description: str = "",
        attributes: list[str] | None = None,
    ) -> str:
        """Add an entity and return its id."""
        identifier = f"entity:{name}"
        self.graph.add_node(
            identifier,
            kind="entity",
            name=name,
            description=description,
            attributes=list(attributes or []),
        )
        return identifier

    def add_file(self, path: str) -> str:
        """Add a file of the code and return its id."""
        identifier = f"file:{path}"
        self.graph.add_node(identifier, kind="file", name=path, path=path)
        return identifier

    def add_relationship(self, source: str, target: str, kind: str = "references") -> None:
        """Add a relation between two entities."""
        if kind not in _RELATIONSHIP_KINDS:
            raise ValueError(f"unknown relationship kind '{kind}'")
        source_id = f"entity:{source}"
        target_id = f"entity:{target}"
        if source_id not in self.graph or target_id not in self.graph:
            return
        self.graph.add_edge(source_id, target_id, kind=kind)

    def add_handles(self, path: str, entity: str) -> None:
        """Link a file of the code to the entity it implements."""
        file_id = f"file:{path}"
        entity_id = f"entity:{entity}"
        if file_id not in self.graph or entity_id not in self.graph:
            return
        self.graph.add_edge(file_id, entity_id, kind="handles")

    # --- queries -------------------------------------------------------

    def entities(self) -> list[str]:
        """Every entity of the graph."""
        return sorted(
            str(self.graph.nodes[node].get("name", ""))
            for node in self.graph.nodes
            if self.graph.nodes[node].get("kind") == "entity"
        )

    def relationships(self) -> list[tuple[str, str, str]]:
        """Every relation between two entities."""
        found: list[tuple[str, str, str]] = []
        for source, target in self.graph.edges:
            kind = str(self.graph.edges[source, target].get("kind", ""))
            if kind not in _RELATIONSHIP_KINDS:
                continue
            found.append(
                (
                    str(self.graph.nodes[source].get("name", "")),
                    str(self.graph.nodes[target].get("name", "")),
                    kind,
                )
            )
        return sorted(found)

    def handlers(self, entity: str) -> list[str]:
        """The files of the code that implement an entity."""
        entity_id = f"entity:{entity}"
        if entity_id not in self.graph:
            return []
        return sorted(
            str(self.graph.nodes[source].get("path", ""))
            for source in self.graph.predecessors(entity_id)
            if self.graph.edges[source, entity_id].get("kind") == "handles"
        )

    def to_json(self) -> dict[str, Any]:
        """The graph as a JSON document."""
        return {
            "requirement_id": self.requirement_id,
            "nodes": [
                {"id": str(node), **dict(self.graph.nodes[node])}
                for node in sorted(self.graph.nodes)
            ],
            "edges": [
                {
                    "source": str(source),
                    "target": str(target),
                    "kind": str(self.graph.edges[source, target].get("kind", "")),
                }
                for source, target in sorted(self.graph.edges)
            ],
        }

    @classmethod
    def from_json(cls, data: dict[str, Any]) -> DomainGraph:
        """Read a graph back from its JSON document."""
        graph: nx.DiGraph[str] = nx.DiGraph()
        for node in data.get("nodes", []):
            identifier = str(node.pop("id"))
            graph.add_node(identifier, **node)
        for edge in data.get("edges", []):
            graph.add_edge(
                str(edge["source"]),
                str(edge["target"]),
                kind=str(edge.get("kind", "")),
            )
        return cls(
            graph=graph,
            requirement_id=str(data.get("requirement_id", "")),
        )

    def save(self, path: Path) -> Path:
        """Write the graph to a JSON file."""
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(self.to_json(), indent=2, sort_keys=True), encoding="utf-8"
        )
        return path

    @classmethod
    def load(cls, path: Path) -> DomainGraph:
        """Read a graph from a JSON file."""
        return cls.from_json(json.loads(path.read_text(encoding="utf-8")))


def build_domain_graph(
    spec: RequirementSpec,
    *,
    repo: RepoGraph | None = None,
) -> DomainGraph:
    """Build the domain graph of a requirement.

    The entities and the relations are read from the specification. When the
    repository graph is given, the files that implement an entity are linked
    to it with a ``handles`` edge.
    """
    graph = DomainGraph(requirement_id=spec.requirement_id)

    for described in spec.entities:
        graph.add_entity(described.name, described.description, described.attributes)
    for name in spec.domain_entities:
        if f"entity:{name}" not in graph.graph:
            graph.add_entity(name)

    for relationship in spec.relationships:
        graph.add_relationship(
            relationship.source, relationship.target, relationship.kind
        )

    if repo is not None:
        for path in repo.file_paths():
            graph.add_file(path)
        for name in graph.entities():
            for path in repo.file_paths():
                if _implements(path, name):
                    graph.add_handles(path, name)
            for handler in _symbol_handlers(repo, name):
                graph.add_file(handler)
                graph.add_handles(handler, name)

    return graph


def _implements(path: str, entity: str) -> bool:
    """Whether a file of the code implements an entity."""
    stem = Path(path).stem
    return _snake(entity) in (stem, _snake(stem))


def _symbol_handlers(repo: RepoGraph, entity: str) -> list[str]:
    """The files that hold a class or a function named after the entity."""
    wanted = _snake(entity)
    handlers: list[str] = []
    for node in repo.graph.nodes:
        data = repo.graph.nodes[node]
        if data.get("kind") not in ("class", "function"):
            continue
        name = str(data.get("name", ""))
        if name and _snake(name) == wanted:
            path = str(data.get("path", ""))
            if path and path not in handlers:
                handlers.append(path)
    return handlers
