"""High risk acceptance approvals stay linked to the orchestration run."""

from __future__ import annotations

from pathlib import Path

from oracle_hcm.log.conversation import ConversationStore
from oracle_hcm.schemas.artifacts import ExecutionReport, RequirementSpec, RiskTier, TestSuite
from oracle_hcm.security.ast_policy import AstPolicy
from oracle_hcm.security.risk import RiskClassifier
from oracle_hcm.services.acceptance import AcceptanceGateAgent, RiskTierGate
from oracle_hcm.services.approvals import ApprovalService
from oracle_hcm.services.sandbox import CommandResult, SandboxService
from oracle_hcm.sop.models import GateSpec


async def test_risk_assessment_approval_uses_the_real_run_and_is_persisted(
    tmp_path: Path,
) -> None:
    approvals = ApprovalService(tmp_path / "approvals")
    agent = AcceptanceGateAgent(
        sandbox=SandboxService(),
        approvals=approvals,
        classifier=RiskClassifier(AstPolicy()),
        declared_tier=RiskTier.HIGH,
    )
    result = await agent(
        {
            "run_id": "run-real-id",
            "tenant_id": "tenant-real",
            "report": ExecutionReport(
                run_id="execution-output-id",
                requirement_id="REQ-1",
                command="pytest",
                exit_code=0,
            ).model_dump(mode="json"),
            "security": ExecutionReport(
                run_id="security-output-id",
                requirement_id="REQ-1",
                command="security",
                exit_code=0,
            ).model_dump(mode="json"),
            "tests": TestSuite(suite_id="SUITE-1", requirement_id="REQ-1").model_dump(
                mode="json"
            ),
            "spec": RequirementSpec(
                requirement_id="REQ-1",
                title="Payroll adjustment",
                description="Update payroll calculations.",
                acceptance_criteria=["The payroll adjustment is recorded."],
            ).model_dump(mode="json"),
        }
    )

    assert result.acceptance is not None
    assert result.acceptance.approval_id is not None
    persisted = ApprovalService(tmp_path / "approvals").get(result.acceptance.approval_id)
    assert persisted is not None
    assert persisted.status == "pending"
    assert persisted.run_id == "run-real-id"
    assert persisted.tenant_id == "tenant-real"
    assert persisted.gate_id == "risk_tier"
    assert persisted.stage == 0
    assert persisted.artifact_type == "risk_assessment"

    gate = GateSpec(
        gate_id="risk_tier",
        type="risk_tier",
        params={"artifact": "acceptance_gate", "min_approval": "high"},
    )
    outcome = await RiskTierGate(approvals).evaluate(
        gate,
        {
            "run_id": "run-real-id",
            "tenant_id": "tenant-real",
            "outputs": {"acceptance_gate": result},
        },
    )
    assert outcome.status == "pending_approval"


async def test_failed_test_collection_is_reported_as_not_passing_requirement_coverage(
    tmp_path: Path,
) -> None:
    agent = AcceptanceGateAgent(
        sandbox=SandboxService(),
        approvals=ApprovalService(tmp_path / "approvals"),
        classifier=RiskClassifier(AstPolicy()),
        declared_tier=RiskTier.LOW,
    )
    result = await agent(
        {
            "report": ExecutionReport(
                run_id="execution-output-id",
                requirement_id="REQ-1",
                command="pytest",
                exit_code=2,
                tests_failed=1,
            ),
            "security": ExecutionReport(
                run_id="security-output-id",
                requirement_id="REQ-1",
                command="security",
                exit_code=0,
            ),
            "tests": TestSuite(suite_id="SUITE-1", requirement_id="REQ-1"),
        }
    )

    assert result.acceptance is not None
    coverage = next(
        condition
        for condition in result.acceptance.conditions
        if condition.name == "requirements_covered"
    )
    assert coverage.passed is False
    assert coverage.detail == "1 test(s) failed or could not be collected"


class QualityCheckSandbox:
    """Return controlled pytest and mypy output for acceptance diagnostics."""

    def __init__(self, *, repaired: bool, unimported_target: bool = False) -> None:
        self.repaired = repaired
        self.unimported_target = unimported_target
        self.commands: list[list[str]] = []

    def pytest_command(self, targets: list[str]) -> list[str]:
        modules = [target.removesuffix(".py") for target in targets]
        args = ["pytest"]
        for module in modules:
            args.extend(["--cov", module])
        return [*args, "--cov-report", "term"]

    def mypy_command(self, targets: list[str]) -> list[str]:
        return ["mypy", "--strict", *targets]

    async def run_in_directory(
        self,
        *,
        directory: Path,
        commands: list[list[str]],
        timeout_seconds: int | None = None,
    ) -> list[CommandResult]:
        del directory, timeout_seconds
        self.commands.extend(commands)
        command = commands[0]
        if command[0] == "mypy":
            return [
                CommandResult(
                    command=" ".join(command),
                    exit_code=0 if self.repaired else 1,
                    stdout=(
                        ""
                        if self.repaired
                        else (
                            "microservice.py:33: error: Missing type arguments "
                            "for generic dict [type-arg]"
                        )
                    ),
                    stderr="",
                    timed_out=False,
                    duration_seconds=0.1,
                )
            ]
        pytest_result = CommandResult(
            command=" ".join(command),
            exit_code=0,
            stdout=(
                "TOTAL 32 4 88%\n"
                if self.unimported_target
                else (
                    "1 passed\nTOTAL 10 0 100%\n"
                    if self.repaired
                    else ".\nWARNING: Failed to generate report: No data to report.\n"
                )
            ),
            stderr=(
                "CoverageWarning: Module microservice was never imported;"
                if self.unimported_target
                else (
                    ""
                    if self.repaired
                    else (
                        "CoverageWarning: Module microservice.py was never imported; "
                        "no data was collected."
                    )
                )
            ),
            timed_out=False,
            duration_seconds=0.1,
        )
        return [pytest_result for _ in commands]


def _acceptance_agent(
    sandbox: SandboxService | QualityCheckSandbox,
    tmp_path: Path,
    conversations: ConversationStore | None = None,
) -> AcceptanceGateAgent:
    return AcceptanceGateAgent(
        sandbox=sandbox,  # type: ignore[arg-type]
        approvals=ApprovalService(tmp_path / "approvals"),
        classifier=RiskClassifier(AstPolicy()),
        conversations=conversations,
    )


async def test_quality_failures_keep_full_mypy_and_coverage_diagnostics(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "microservice.py").write_text("value: dict = {}\n", encoding="utf-8")
    sandbox = QualityCheckSandbox(repaired=False)
    conversations = ConversationStore(tmp_path / "conversations")
    agent = _acceptance_agent(sandbox, tmp_path, conversations)
    report = ExecutionReport(
        run_id="failed-quality-run",
        requirement_id="REQ-1",
        command="pytest",
        exit_code=0,
        tests_passed=1,
        workspace_path=str(workspace),
    )

    result = await agent(
        {
            "report": report,
            "security": ExecutionReport(
                run_id="security", requirement_id="REQ-1", command="security", exit_code=0
            ),
            "tests": TestSuite(suite_id="SUITE-1", requirement_id="REQ-1"),
        }
    )

    assert ["mypy", "--strict", "microservice.py"] in sandbox.commands
    assert ["pytest", "--cov", "microservice", "--cov-report", "term"] in sandbox.commands
    assert result.mypy_clean is False
    assert "microservice.py:33: error" in result.mypy_output
    assert result.acceptance is not None
    assert "Missing type arguments" in result.acceptance.conditions[1].detail
    assert result.coverage_percent == 0.0
    assert "never imported" in result.coverage_diagnostic
    assert "no data was collected" in result.acceptance.conditions[2].detail
    stored = conversations.read_all()
    assert len(stored) == 1
    assert stored[0].role == "quality_gate"
    assert stored[0].metadata["attempted_repairs"] == 0
    assert stored[0].metadata["outcome"] == "failed"


async def test_clean_quality_rerun_passes_without_losing_the_coverage_threshold(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "microservice.py").write_text("value: dict[str, int] = {}\n", encoding="utf-8")
    sandbox = QualityCheckSandbox(repaired=True)
    agent = _acceptance_agent(sandbox, tmp_path)
    report = ExecutionReport(
        run_id="repaired-quality-run",
        requirement_id="REQ-1",
        command="pytest",
        exit_code=0,
        tests_passed=1,
        coverage_percent=100.0,
        workspace_path=str(workspace),
    )

    result = await agent(
        {
            "report": report,
            "security": ExecutionReport(
                run_id="security", requirement_id="REQ-1", command="security", exit_code=0
            ),
            "tests": TestSuite(suite_id="SUITE-1", requirement_id="REQ-1"),
        }
    )

    assert result.mypy_clean is True
    assert result.mypy_output == ""
    assert result.acceptance is not None
    assert result.coverage_percent == 100.0
    assert result.coverage_diagnostic == ""
    assert result.acceptance.conditions[1].passed is True
    assert result.acceptance.conditions[2].passed is True


async def test_coverage_report_does_not_pass_when_a_requested_module_was_not_imported(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "microservice.py").write_text("value: int = 1\n", encoding="utf-8")
    sandbox = QualityCheckSandbox(repaired=True, unimported_target=True)
    result = await _acceptance_agent(sandbox, tmp_path)(
        {
            "report": ExecutionReport(
                run_id="unimported-quality-run",
                requirement_id="REQ-1",
                command="pytest",
                exit_code=0,
                tests_passed=1,
                workspace_path=str(workspace),
            ),
            "security": ExecutionReport(
                run_id="security", requirement_id="REQ-1", command="security", exit_code=0
            ),
            "tests": TestSuite(suite_id="SUITE-1", requirement_id="REQ-1"),
        }
    )

    assert result.coverage_percent == 88.0
    assert result.acceptance is not None
    condition = result.acceptance.conditions[2]
    assert condition.passed is False
    assert "coverage target was not exercised" in condition.detail
