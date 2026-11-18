"""The results tables of the knowledge evaluation.

The tables in docs/knowledge_evaluation.md are generated from the outcomes the
knowledge scenarios observed. The test fails when the file and the observations
disagree, so a refusal or a leak that did not happen can never be hidden by
editing the document.
"""

from __future__ import annotations

from typing import Any

import pytest

from knowledge_report import build_report, report_path, scenarios
from oracle_hcm.knowledge.vectors import qdrant_client


def qdrant_is_ready() -> bool:
    """Whether the Qdrant container answers."""
    try:
        qdrant_client().get_collections()
    except Exception:
        return False
    return True


pytestmark = [
    pytest.mark.skipif(not qdrant_is_ready(), reason="the qdrant container does not answer"),
]


@pytest.fixture(scope="module")
def outcomes() -> tuple[Any, ...]:
    """Run every knowledge scenario once."""
    return scenarios()


def test_the_report_holds_the_results_of_the_scenarios(outcomes: tuple[Any, ...]) -> None:
    path = report_path()

    assert path.is_file(), f"the report is missing: {path}"
    assert path.read_text(encoding="utf-8") == build_report(*outcomes), (
        "the report is out of date, regenerate it with 'python tests/knowledge_report.py'"
    )


def test_the_graph_was_built_without_executing_the_code(outcomes: tuple[Any, ...]) -> None:
    graph, _, _, _, _, _ = outcomes

    assert graph.node_kinds["file"] == 3
    assert graph.node_kinds["class"] == 2
    assert graph.node_kinds["function"] == 3
    assert graph.node_kinds["test"] == 1
    assert graph.edge_kinds["defines"] > 0
    assert graph.edge_kinds["imports"] == 3
    assert graph.edge_kinds["calls"] == 1
    assert graph.edge_kinds["tests"] == 2
    assert graph.edge_kinds["produced_by"] == 3
    assert graph.parse_errors == []
    assert "pkg/attendance.py" in graph.impact
    assert "tests/test_attendance.py" in graph.impact


def test_the_domain_graph_links_the_entities_to_the_code(outcomes: tuple[Any, ...]) -> None:
    _, domain, _, _, _, _ = outcomes

    assert domain.entities == ["Attendance", "Employee", "Punch"]
    assert ("Attendance", "Employee", "belongs_to") in domain.relationships
    assert ("Punch", "Attendance", "references") in domain.relationships
    assert domain.handlers["Employee"] == ["pkg/employee.py"]
    assert domain.handlers["Attendance"] == ["pkg/attendance.py"]


def test_the_store_kept_the_tenants_apart(outcomes: tuple[Any, ...]) -> None:
    _, _, store, _, _, _ = outcomes

    assert store.own_points == 1
    assert store.other_points == 0
    assert store.own_hits == 1
    assert store.other_hits == 0
    assert store.ids_stable is True
    assert store.points_after_the_second_write == 1


def test_the_retrieval_redacted_and_wrapped_the_data(outcomes: tuple[Any, ...]) -> None:
    _, _, _, retrieval, _, _ = outcomes

    assert retrieval.secret_redacted is True
    assert retrieval.personal_data_redacted is True
    assert retrieval.injection_wrapped is True
    assert retrieval.wrappers == retrieval.items
    assert retrieval.items == 2
    assert retrieval.top_k <= 3


def test_the_test_designer_saw_no_code_before_the_freeze(outcomes: tuple[Any, ...]) -> None:
    _, _, _, retrieval, _, _ = outcomes

    assert retrieval.designer_before_freeze < retrieval.designer_after_freeze
    assert retrieval.designer_after_freeze == retrieval.coder


def test_only_a_signed_deployment_reached_the_memory(outcomes: tuple[Any, ...]) -> None:
    _, _, _, _, memory, _ = outcomes

    assert memory.episodic_points == 1
    assert memory.repo_points == 5
    assert memory.audit_event == "qdrant_updated"
    assert memory.unsigned_episodic_points == 0
    assert memory.graph_files == ["repo.json"]
    assert any("Artifact hash:" in line for line in memory.summary_lines)


def test_the_conversation_record_is_redacted(outcomes: tuple[Any, ...]) -> None:
    _, _, _, _, _, conversation = outcomes

    assert conversation.redacted is True
    assert conversation.tokens == 30
    for field in (
        "role",
        "model",
        "model_version",
        "parameters",
        "attempt",
        "prompt_tokens",
        "completion_tokens",
        "latency_ms",
        "correlation_id",
        "run_id",
        "tenant_id",
    ):
        assert field in conversation.fields
