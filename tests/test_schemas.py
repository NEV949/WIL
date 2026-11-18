"""Artifact schemas."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from oracle_hcm.schemas.artifacts import (
    CodePatch,
    DebugPatch,
    ExecutionReport,
    FileChange,
    PlanStep,
    RequirementSpec,
    RiskTier,
    TaskPlan,
    TestCase,
    TestSuite,
)


def test_requirement_spec_requires_acceptance_criteria() -> None:
    with pytest.raises(ValidationError):
        RequirementSpec(requirement_id="R-1", title="t", description="d", acceptance_criteria=[])


def test_file_change_rejects_path_traversal() -> None:
    with pytest.raises(ValidationError):
        FileChange(path="../outside.py", operation="create")
    with pytest.raises(ValidationError):
        FileChange(path="/etc/passwd", operation="modify")


def test_task_plan_round_trips() -> None:
    plan = TaskPlan(
        plan_id="P-1",
        requirement_id="R-1",
        steps=[PlanStep(step_id="s1", description="write module", target_files=["pkg/mod.py"])],
    )
    assert plan.steps[0].target_files == ["pkg/mod.py"]
    assert plan.schema_version == "1.0"


def test_code_patch_carries_file_changes() -> None:
    patch = CodePatch(
        patch_id="CP-1",
        requirement_id="R-1",
        files=[FileChange(path="pkg/mod.py", operation="create", content="x = 1")],
    )
    assert patch.files[0].operation == "create"


def test_test_suite_reports_covered_requirements() -> None:
    suite = TestSuite(
        suite_id="TS-1",
        requirement_id="R-1",
        tests=[
            TestCase(test_id="t1", requirement_ids=["R-1"], target_module="pkg.mod", test_code=""),
            TestCase(test_id="t2", requirement_ids=["R-2"], target_module="pkg.mod", test_code=""),
        ],
    )
    assert suite.covered_requirement_ids() == {"R-1", "R-2"}


def test_execution_report_defaults() -> None:
    report = ExecutionReport(run_id="RUN-1", requirement_id="R-1", command="pytest", exit_code=0)
    assert report.tests_passed == 0
    assert report.mypy_clean is False
    assert report.security_events == []


def test_debug_patch_requires_positive_attempt() -> None:
    with pytest.raises(ValidationError):
        DebugPatch(patch_id="DP-1", requirement_id="R-1", attempt=0)


def test_risk_tier_can_only_be_raised() -> None:
    assert RiskTier.HIGH.at_least(RiskTier.MEDIUM)
    assert not RiskTier.LOW.at_least(RiskTier.MEDIUM)
    assert RiskTier.HIGH.rank > RiskTier.MEDIUM.rank > RiskTier.LOW.rank


def test_artifacts_reject_unknown_fields() -> None:
    with pytest.raises(ValidationError):
        TaskPlan(plan_id="P-1", requirement_id="R-1", unexpected="x")  # type: ignore[call-arg]
