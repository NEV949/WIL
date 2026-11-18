"""The repository graph.

The graph describes the code of a workspace: which files exist, which classes
and functions they define, what imports what, what calls what and which test
exercises which function. The sources are parsed with :func:`ast.parse` and
are never executed, so an unknown or hostile file cannot run inside the
engine.

The graph is stored as JSON under ``data/graph/`` and is rebuilt after every
accepted deployment.
"""

from __future__ import annotations

import ast
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import networkx as nx

from oracle_hcm.paths import data_dir

__all__ = [
    "EDGE_KINDS",
    "NODE_KINDS",
    "RepoGraph",
    "build_repo_graph",
    "graph_dir",
    "node_id",
]

NODE_KINDS: tuple[str, ...] = ("file", "class", "function", "test", "artifact")
EDGE_KINDS: tuple[str, ...] = ("imports", "defines", "calls", "tests", "produced_by")

SKIPPED_DIRECTORIES: frozenset[str] = frozenset(
    {
        ".git",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        ".venv",
        "__pycache__",
        "build",
        "dist",
        "node_modules",
    }
)


def graph_dir() -> Path:
    """Where the graph documents live."""
    return data_dir() / "graph"


def node_id(kind: str, identifier: str) -> str:
    """The id of a node in the graph."""
    return f"{kind}:{identifier}"


@dataclass
class RepoGraph:
    """The graph of one workspace."""

    graph: nx.DiGraph[str] = field(default_factory=nx.DiGraph)
    artifact_hash: str = ""
    parse_errors: list[str] = field(default_factory=list)

    # --- construction --------------------------------------------------

    def add_node(self, identifier: str, kind: str, **attributes: Any) -> str:
        """Add a node and return its id."""
        if kind not in NODE_KINDS:
            raise ValueError(f"unknown node kind '{kind}'")
        identifier = node_id(kind, identifier)
        self.graph.add_node(identifier, kind=kind, **attributes)
        return identifier

    def add_edge(self, source: str, target: str, kind: str) -> None:
        """Add an edge between two nodes."""
        if kind not in EDGE_KINDS:
            raise ValueError(f"unknown edge kind '{kind}'")
        if source not in self.graph or target not in self.graph:
            return
        self.graph.add_edge(source, target, kind=kind)

    # --- queries -------------------------------------------------------

    def nodes_of_kind(self, kind: str) -> list[str]:
        """Every node id of one kind."""
        return sorted(
            str(node)
            for node in self.graph.nodes
            if self.graph.nodes[node].get("kind") == kind
        )

    def file_paths(self) -> list[str]:
        """Every file of the workspace, relative and sorted."""
        return sorted(
            str(self.graph.nodes[node].get("path", ""))
            for node in self.graph.nodes
            if self.graph.nodes[node].get("kind") == "file"
        )

    def edges_of_kind(self, kind: str) -> list[tuple[str, str]]:
        """Every edge of one kind."""
        return sorted(
            (str(source), str(target))
            for source, target in self.graph.edges
            if self.graph.edges[source, target].get("kind") == kind
        )

    def impact(self, target: str) -> list[str]:
        """The files that are affected when the target changes.

        The target may be a node id, a file path or the name of a function or
        a class. A file is affected when it holds the target or when it
        depends on it, directly or through another symbol.
        """
        start = self._resolve(target)
        if start is None:
            return []
        dependents = {start} | set(nx.descendants(self.graph.reverse(copy=False), start))
        affected = {
            str(self.graph.nodes[node].get("path", ""))
            for node in dependents
            if self.graph.nodes[node].get("kind") == "file"
        }
        return sorted(path for path in affected if path)

    def _resolve(self, target: str) -> str | None:
        """Find the node a target names."""
        if target in self.graph:
            return target
        for kind in NODE_KINDS:
            candidate = node_id(kind, target)
            if candidate in self.graph:
                return candidate
        matches = [
            str(node)
            for node in self.graph.nodes
            if self.graph.nodes[node].get("name") == target
            or self.graph.nodes[node].get("path") == target
        ]
        if len(matches) == 1:
            return matches[0]
        return None

    # --- persistence ---------------------------------------------------

    def to_json(self) -> dict[str, Any]:
        """The graph as a JSON document."""
        return {
            "artifact_hash": self.artifact_hash,
            "parse_errors": list(self.parse_errors),
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
    def from_json(cls, data: dict[str, Any]) -> RepoGraph:
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
            artifact_hash=str(data.get("artifact_hash", "")),
            parse_errors=[str(item) for item in data.get("parse_errors", [])],
        )

    def save(self, path: Path) -> Path:
        """Write the graph to a JSON file."""
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(self.to_json(), indent=2, sort_keys=True), encoding="utf-8"
        )
        return path

    @classmethod
    def load(cls, path: Path) -> RepoGraph:
        """Read a graph from a JSON file."""
        return cls.from_json(json.loads(path.read_text(encoding="utf-8")))


def _module_name(relative: Path) -> str:
    """The importable name of a file, without its extension."""
    parts = list(relative.with_suffix("").parts)
    if parts and parts[-1] == "__init__":
        parts.pop()
    return ".".join(parts)


def _is_test_path(relative: str) -> bool:
    """Whether a file belongs to the test suite."""
    path = Path(relative)
    return path.name.startswith("test_") or path.parts[0] == "tests"


def _python_files(workspace: Path) -> list[str]:
    """Every python file of a workspace, relative and sorted."""
    found: list[str] = []
    for path in workspace.rglob("*.py"):
        relative = path.relative_to(workspace)
        if any(part in SKIPPED_DIRECTORIES for part in relative.parts):
            continue
        found.append(relative.as_posix())
    return sorted(found)


def _imported_modules(tree: ast.AST) -> set[str]:
    """Every module a file imports."""
    modules: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            modules.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            if node.level:
                continue
            if node.module:
                modules.add(node.module)
    return modules


def _called_names(node: ast.AST) -> set[str]:
    """Every name a function calls."""
    names: set[str] = set()
    for child in ast.walk(node):
        if isinstance(child, ast.Call):
            target = child.func
            if isinstance(target, ast.Name):
                names.add(target.id)
            elif isinstance(target, ast.Attribute):
                names.add(target.attr)
    return names


def build_repo_graph(workspace: Path, *, artifact_hash: str = "") -> RepoGraph:
    """Build the graph of a workspace by parsing its sources.

    The files are parsed with :func:`ast.parse`; nothing in the workspace is
    imported or executed.
    """
    graph = RepoGraph(artifact_hash=artifact_hash)
    if artifact_hash:
        graph.add_node(artifact_hash, "artifact", name=artifact_hash)

    files = _python_files(workspace)
    module_index: dict[str, str] = {}
    for relative in files:
        module_index.setdefault(
            _module_name(Path(relative)), node_id("file", relative)
        )
    module_index.setdefault("", node_id("file", ""))

    parsed: dict[str, ast.Module] = {}
    for relative in files:
        path = workspace / relative
        source = path.read_text(encoding="utf-8", errors="replace")
        try:
            tree = ast.parse(source, filename=relative)
        except SyntaxError as exc:
            graph.parse_errors.append(f"{relative}: {exc.msg}")
            continue
        parsed[relative] = tree

    symbol_index: dict[str, list[str]] = {}
    owners: dict[int, str] = {}
    for relative, tree in parsed.items():
        file_node = graph.add_node(relative, "file", path=relative, name=relative)
        _collect_symbols(graph, file_node, relative, tree, symbol_index, owners)

    for relative, tree in parsed.items():
        file_node = node_id("file", relative)
        for module in sorted(_imported_modules(tree)):
            target = module_index.get(module)
            if target is not None and target != file_node:
                graph.add_edge(file_node, target, "imports")
        _collect_calls(graph, relative, tree, symbol_index, owners)

    if artifact_hash:
        artifact_node = node_id("artifact", artifact_hash)
        for file_path in graph.file_paths():
            graph.add_edge(node_id("file", file_path), artifact_node, "produced_by")

    return graph


def _collect_symbols(
    graph: RepoGraph,
    file_node: str,
    relative: str,
    tree: ast.Module,
    symbol_index: dict[str, list[str]],
    owners: dict[int, str],
) -> None:
    """Add the classes and functions of a file to the graph.

    The owner of every function is remembered, so that the call edges can be
    attached to the function that holds the call.
    """
    is_test_file = _is_test_path(relative)
    for node in tree.body:
        if isinstance(node, ast.ClassDef):
            class_node = graph.add_node(
                f"{relative}::{node.name}", "class", name=node.name, path=relative
            )
            graph.add_edge(file_node, class_node, "defines")
            symbol_index.setdefault(node.name, []).append(class_node)
            for member in node.body:
                if isinstance(member, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    kind = "test" if is_test_file else "function"
                    symbol = graph.add_node(
                        f"{relative}::{node.name}::{member.name}",
                        kind,
                        name=member.name,
                        path=relative,
                    )
                    graph.add_edge(class_node, symbol, "defines")
                    graph.add_edge(file_node, symbol, "defines")
                    symbol_index.setdefault(member.name, []).append(symbol)
                    owners[id(member)] = symbol
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            kind = "test" if is_test_file or node.name.startswith("test_") else "function"
            symbol = graph.add_node(
                f"{relative}::{node.name}", kind, name=node.name, path=relative
            )
            graph.add_edge(file_node, symbol, "defines")
            symbol_index.setdefault(node.name, []).append(symbol)
            owners[id(node)] = symbol


def _collect_calls(
    graph: RepoGraph,
    relative: str,
    tree: ast.Module,
    symbol_index: dict[str, list[str]],
    owners: dict[int, str],
) -> None:
    """Add the call and test edges of a file to the graph."""
    is_test_file = _is_test_path(relative)
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        owner = owners.get(id(node))
        if owner is None:
            continue
        for name in sorted(_called_names(node)):
            targets = symbol_index.get(name, [])
            if len(targets) != 1:
                continue
            target = targets[0]
            if target == owner:
                continue
            kind = "tests" if is_test_file else "calls"
            graph.add_edge(owner, target, kind)
