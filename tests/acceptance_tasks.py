"""The two tasks of the end to end acceptance run.

The tasks are defined here so that the acceptance test and the security
evaluation report always speak about the same code. The pipeline runs the
suite, the scanners and the type checker in the sandbox image for real.
"""

from __future__ import annotations

import tempfile
from dataclasses import dataclass
from pathlib import Path

from oracle_hcm.schemas.artifacts import (
    AcceptanceCondition,
    CodePatch,
    ExecutionReport,
    FileChange,
    RequirementSpec,
    TestCase,
    TestSuite,
)
from oracle_hcm.security.ast_policy import AstPolicy
from oracle_hcm.security.prompt_guard import RegexPromptGuard
from oracle_hcm.security.risk import RiskClassifier
from oracle_hcm.security.scanners import ScannerSuite
from oracle_hcm.services.acceptance import AcceptanceGateAgent
from oracle_hcm.services.approvals import ApprovalService
from oracle_hcm.services.sandbox import SandboxConfig, SandboxRunnerAgent, SandboxService
from oracle_hcm.services.security_gate import (
    PreRunSecurityGate,
    RequirementChecker,
    SecurityGateAgent,
)

__all__ = [
    "Outcome",
    "blocked_task",
    "outcomes",
    "passing_task",
    "root_directory",
    "run_task",
]

LABEL_SOURCE = (
    '"""Label helper for leave requests."""\n'
    "\n"
    "\n"
    "def label(kind: str, days: int) -> str:\n"
    '    """Build the label of a leave request."""\n'
    '    return f"{kind}: {days} days"\n'
)

LABEL_TEST = (
    "from pkg.label import label\n"
    "\n"
    "\n"
    "def test_the_label_holds_the_kind_and_the_days() -> None:\n"
    '    assert label("annual", 3) == "annual: 3 days"\n'
)

REPORT_SOURCE = (
    '"""Report helper for leave requests."""\n'
    "\n"
    "\n"
    "def headline(count: int) -> str:\n"
    '    """The headline of a report."""\n'
    '    return f"{count} records"\n'
    "\n"
    "\n"
    "def footer(count: int) -> str:\n"
    '    """The footer of a report."""\n'
    '    return f"{count} of {count} records"\n'
    "\n"
    "\n"
    "def broken(count: int) -> int:\n"
    '    """Returns a string on purpose."""\n'
    '    return f"{count}"\n'
)

REPORT_TEST = (
    "from pkg.report import headline\n"
    "\n"
    "\n"
    "def test_the_headline_holds_the_number_of_records() -> None:\n"
    '    assert headline(3) == "4 records"\n'
)


@dataclass(frozen=True)
class Outcome:
    """Everything the three stages of a task produced."""

    name: str
    run: ExecutionReport
    security: ExecutionReport
    acceptance: ExecutionReport

    @property
    def conditions(self) -> dict[str, AcceptanceCondition]:
        result = self.acceptance.acceptance
        assert result is not None
        return {condition.name: condition for condition in result.conditions}

    def verdicts(self) -> dict[str, bool]:
        return {name: condition.passed for name, condition in self.conditions.items()}


def passing_task() -> tuple[RequirementSpec, CodePatch, TestSuite]:
    """A task that passes every acceptance condition."""
    spec = RequirementSpec(
        requirement_id="REQ-LABEL",
        title="Add a label helper for leave requests",
        description=(
            "Builds the label of a leave request from its kind and its duration in days."
        ),
        acceptance_criteria=["The label holds the kind and the number of days."],
        domain_entities=["LeaveRequest"],
    )
    patch = CodePatch(
        patch_id="PATCH-LABEL",
        requirement_id="REQ-LABEL",
        summary="Add the label helper.",
        files=[FileChange(path="pkg/label.py", operation="create", content=LABEL_SOURCE)],
    )
    suite = TestSuite(
        suite_id="SUITE-LABEL",
        requirement_id="REQ-LABEL",
        tests=[
            TestCase(
                test_id="test-label",
                requirement_ids=["REQ-LABEL"],
                target_module="pkg.label",
                test_code=LABEL_TEST,
            )
        ],
    )
    return spec, patch, suite


def blocked_task() -> tuple[RequirementSpec, CodePatch, TestSuite]:
    """A task that breaks four acceptance conditions."""
    spec = RequirementSpec(
        requirement_id="REQ-REPORT",
        title="Add a report helper for leave requests",
        description="Builds the headline and the footer of a leave request report.",
        acceptance_criteria=["The headline holds the number of records."],
        domain_entities=["LeaveRequest"],
    )
    patch = CodePatch(
        patch_id="PATCH-REPORT",
        requirement_id="REQ-REPORT",
        summary="Add the report helper.",
        files=[FileChange(path="pkg/report.py", operation="create", content=REPORT_SOURCE)],
    )
    suite = TestSuite(
        suite_id="SUITE-REPORT",
        requirement_id="REQ-REPORT",
        tests=[
            TestCase(
                test_id="test-report",
                requirement_ids=["REQ-OTHER"],
                target_module="pkg.report",
                test_code=REPORT_TEST,
            )
        ],
    )
    return spec, patch, suite


async def run_task(
    directory: Path,
    name: str,
    spec: RequirementSpec,
    patch: CodePatch,
    suite: TestSuite,
) -> Outcome:
    """Run one task through the sandbox, the security gate and the acceptance."""
    service = SandboxService(config=SandboxConfig(timeout_seconds=300))
    scanners = ScannerSuite()
    policy = AstPolicy()
    classifier = RiskClassifier(policy)
    approvals = ApprovalService(directory / "approvals")
    runner = SandboxRunnerAgent(
        service,
        gate=PreRunSecurityGate(scanners=scanners, policy=policy),
        checker=RequirementChecker(policy=policy, guard=RegexPromptGuard()),
        workspace_root=directory / "workspaces",
    )
    run = await runner(
        {
            "run_id": name,
            "code": patch.model_dump(mode="json"),
            "tests": suite.model_dump(mode="json"),
            "spec": spec.model_dump(mode="json"),
        }
    )
    security = await SecurityGateAgent(
        service,
        scanners=scanners,
        policy=policy,
        classifier=classifier,
        guard=RegexPromptGuard(),
    )(
        {
            "report": run.model_dump(mode="json"),
            "spec": spec.model_dump(mode="json"),
        }
    )
    acceptance = await AcceptanceGateAgent(
        service,
        approvals=approvals,
        classifier=classifier,
        coverage_target=80.0,
    )(
        {
            "report": run.model_dump(mode="json"),
            "security": security.model_dump(mode="json"),
            "tests": suite.model_dump(mode="json"),
            "spec": spec.model_dump(mode="json"),
        }
    )
    return Outcome(name=name, run=run, security=security, acceptance=acceptance)


_CACHE: dict[str, Outcome] = {}


def root_directory() -> Path:
    """Where the workspaces and the approvals of the run are kept."""
    return Path(tempfile.gettempdir()) / "oracle-acceptance-e2e"


async def outcomes() -> dict[str, Outcome]:
    """The outcomes of both tasks. The pipeline runs once per session."""
    if _CACHE:
        return _CACHE
    directory = root_directory()
    directory.mkdir(parents=True, exist_ok=True)
    for name, task in (("passing", passing_task), ("blocked", blocked_task)):
        spec, patch, suite = task()
        _CACHE[name] = await run_task(directory, name, spec, patch, suite)
    return _CACHE
