"""The phase 4 gates: risk assessment, security report and acceptance.

The sandbox is replaced by a double that answers the scanners and the suite
the way the sandbox image does, so that the whole gate flow runs without a
container.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from oracle_hcm.app import AppConfig, build_orchestrator
from oracle_hcm.schemas.artifacts import ExecutionReport, RequirementSpec, RiskTier
from oracle_hcm.security.ast_runner import MARKER as AST_MARKER
from oracle_hcm.security.risk import RiskClassifier
from oracle_hcm.services.orchestrator import Orchestrator
from oracle_hcm.services.sandbox import CommandResult

_PYTEST_OUTPUT = "1 passed in 0.1s\nTOTAL   92%\n"


def _stdout_for(command: str) -> str:
    """The output a scanner or the suite would produce in the image."""
    if "ast_runner.py" in command:
        return f"{AST_MARKER}\n[]"
    if "bandit" in command:
        return '{"results": []}'
    if "ruff" in command:
        return "[]"
    if "semgrep" in command:
        return '{"results": []}'
    if "detect-secrets" in command:
        return '{"results": {}}'
    if "mypy" in command:
        return ""
    return _PYTEST_OUTPUT


class GateSandbox:
    """A sandbox double that answers the scanners and the suite like the image."""

    def __init__(self, workspace: Path) -> None:
        self._workspace = workspace
        self.commands: list[str] = []

    async def run(
        self,
        *,
        patch: Any,
        tests: Any,
        debug_patch: Any = None,
        timeout_seconds: int | None = None,
        workspace_dir: Path | None = None,
        gate: Any = None,
    ) -> ExecutionReport:
        return ExecutionReport(
            run_id=f"run-{patch.patch_id}",
            requirement_id=patch.requirement_id,
            command="pytest",
            exit_code=0,
            stdout=_PYTEST_OUTPUT,
            tests_passed=1,
            coverage_percent=92.0,
            workspace_path=str(self._workspace),
        )

    async def run_in_directory(
        self,
        *,
        directory: Path,
        commands: list[list[str]],
        timeout_seconds: int | None = None,
    ) -> list[CommandResult]:
        results: list[CommandResult] = []
        for command in commands:
            joined = " ".join(command)
            self.commands.append(joined)
            results.append(
                CommandResult(
                    command=joined,
                    exit_code=0,
                    stdout=_stdout_for(joined),
                    stderr="",
                    timed_out=False,
                    duration_seconds=0.1,
                )
            )
        return results

    def pytest_command(self, targets: list[str]) -> list[str]:
        return ["pytest", *targets]

    def mypy_command(self, targets: list[str]) -> list[str]:
        return ["mypy", *targets]


@pytest.fixture(autouse=True)
def _no_dependency_audit(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "oracle_hcm.services.security_gate.host_pip_audit",
        lambda *args, **kwargs: [],
    )


def _orchestrator(tmp_path: Path) -> Orchestrator:
    workspace = tmp_path / "workspace"
    (workspace / "pkg").mkdir(parents=True)
    (workspace / "pkg" / "overtime.py").write_text(
        "def overtime_pay(hours: float, rate: float) -> float:\n    return hours * rate\n",
        encoding="utf-8",
    )
    config = AppConfig(sop_id="sop_lightweight", use_fake_backend=True, max_phase=4)
    return build_orchestrator(
        config,
        sandbox=GateSandbox(workspace),  # type: ignore[arg-type]
        data_root=tmp_path,
    )


async def _run_to_the_risk_approval(orchestrator: Orchestrator) -> Any:
    """Run the SOP until the risk tier of the task needs an approval."""
    first = await orchestrator.run("Add overtime pay")
    assert first.approval is not None
    orchestrator._approvals.decide(first.approval.approval_id, approved=True, decided_by="jo")
    second = await orchestrator.resume(first.run_id)
    assert second.approval is not None
    orchestrator._approvals.decide(second.approval.approval_id, approved=True, decided_by="jo")
    third = await orchestrator.resume(second.run_id)
    return third


def _audit_events(tmp_path: Path) -> list[dict[str, Any]]:
    lines = (tmp_path / "audit.jsonl").read_text(encoding="utf-8").splitlines()
    return [json.loads(line) for line in lines if line.strip()]


async def test_the_risk_tier_and_the_signals_are_written_to_the_audit_log(
    tmp_path: Path,
) -> None:
    orchestrator = _orchestrator(tmp_path)

    await _run_to_the_risk_approval(orchestrator)

    events = _audit_events(tmp_path)
    assessed = [event for event in events if event["action"] == "risk_assessed"]
    assert assessed, "the risk assessment is not in the audit log"
    payload = assessed[0]["payload"]
    assert payload["risk_tier"] == "high"
    assert "keyword:payroll" in payload["risk_signals"]
    assert payload["run_id"]
    assert payload["step_id"]


async def test_a_high_risk_task_waits_for_the_approval_of_an_administrator(
    tmp_path: Path,
) -> None:
    orchestrator = _orchestrator(tmp_path)

    result = await _run_to_the_risk_approval(orchestrator)

    assert result.status == "awaiting_approval"
    assert result.approval is not None
    assert result.approval.artifact_type == "risk_assessment"
    assert result.approval.artifact["risk_tier"] == "high"


async def test_the_run_completes_once_the_risk_was_approved(tmp_path: Path) -> None:
    orchestrator = _orchestrator(tmp_path)

    suspended = await _run_to_the_risk_approval(orchestrator)
    assert suspended.approval is not None
    orchestrator._approvals.decide(
        suspended.approval.approval_id, approved=True, decided_by="jo"
    )

    final = await orchestrator.resume(suspended.run_id)

    assert final.status == "completed"
    assert final.sop_result is not None
    acceptance = final.sop_result.outputs["acceptance_gate"]
    assert isinstance(acceptance, ExecutionReport)
    assert acceptance.acceptance is not None
    assert acceptance.acceptance.passed is True
    assert acceptance.acceptance.risk_tier is RiskTier.HIGH


def test_a_declared_tier_is_never_lowered() -> None:
    classifier = RiskClassifier()

    assessment = classifier.classify(None, declared_tier=RiskTier.HIGH)

    assert assessment.tier is RiskTier.HIGH
    assert assessment.signals == ()


def test_the_code_of_the_task_can_raise_the_tier() -> None:
    classifier = RiskClassifier()
    spec = RequirementSpec(
        requirement_id="REQ-1",
        title="Overtime helper",
        description="Calculates overtime.",
        acceptance_criteria=["Overtime is paid at 1.5x."],
    )

    assessment = classifier.classify(
        spec,
        files={"pkg/overtime.py": "import socket\n\n\ndef call():\n    socket.socket()\n"},
        declared_tier=RiskTier.LOW,
    )

    assert assessment.tier is RiskTier.HIGH
    assert "code:network" in assessment.signals


def test_a_sensitive_field_in_the_code_raises_the_tier() -> None:
    classifier = RiskClassifier()

    assessment = classifier.classify(
        None,
        files={"pkg/payroll.py": "def read(record):\n    return record.salary\n"},
        declared_tier=RiskTier.LOW,
    )

    assert assessment.tier is RiskTier.MEDIUM
    assert "code:sensitive_field" in assessment.signals
