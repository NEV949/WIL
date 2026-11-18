"""Acceptance gate.

The gate decides whether the result may be released. It checks that the
suite passes, that the code type checks under mypy --strict, that the
coverage reaches the target, that the security report is clean, that every
requirement is covered by a passing test and that two runs of the suite
agree. A high risk task additionally needs the approval of an administrator.
"""

from __future__ import annotations

import asyncio
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from oracle_hcm.log.conversation import ConversationStore
from oracle_hcm.schemas.artifacts import (
    AcceptanceCondition,
    AcceptanceResult,
    ExecutionReport,
    RequirementSpec,
    RiskTier,
    TestSuite,
)
from oracle_hcm.security.ast_policy import AstPolicy
from oracle_hcm.security.risk import RiskAssessment, RiskClassifier
from oracle_hcm.services.approvals import ApprovalService
from oracle_hcm.services.sandbox import CommandResult, SandboxService, source_targets
from oracle_hcm.sop.engine import GateOutcome
from oracle_hcm.sop.models import GateSpec

__all__ = [
    "AcceptanceGate",
    "AcceptanceGateAgent",
    "RiskTierGate",
    "SecurityCleanGate",
]

_COVERAGE = re.compile(r"TOTAL\s+.*?(\d+(?:\.\d+)?)%")
_RESULT_LINE = re.compile(
    r"^(PASSED|FAILED|ERROR|SKIPPED|XFAIL|XPASS)\s+(\S+)", re.MULTILINE
)


@dataclass(frozen=True)
class AcceptanceGateAgent:
    """The SOP step that decides whether the result may be released."""

    sandbox: SandboxService
    approvals: ApprovalService
    classifier: RiskClassifier
    coverage_target: float = 80.0
    declared_tier: RiskTier = RiskTier.LOW
    conversations: ConversationStore | None = None

    async def __call__(self, payload: dict[str, Any]) -> ExecutionReport:
        report = ExecutionReport.model_validate(payload.get("report", {}))
        raw_spec = payload.get("spec")
        spec = RequirementSpec.model_validate(raw_spec) if raw_spec else None
        suite = TestSuite.model_validate(payload.get("tests", {}))
        security = ExecutionReport.model_validate(payload.get("security", {}))
        run_id = str(payload.get("run_id") or report.run_id)
        tenant_id = str(payload.get("tenant_id", ""))

        conditions: list[AcceptanceCondition] = []
        workspace = Path(report.workspace_path) if report.workspace_path else None
        targets = source_targets(workspace) if workspace and workspace.is_dir() else []
        runs = await self._determinism_runs(workspace, targets)
        mypy_result = await self._mypy_result(workspace, targets)
        mypy_clean = mypy_result is not None and mypy_result.exit_code == 0
        mypy_output = ""
        if mypy_result is not None:
            mypy_output = "\n".join(
                part for part in (mypy_result.stdout, mypy_result.stderr) if part
            ).strip()
        elif not targets:
            mypy_output = "mypy --strict was not run: no source targets were discovered"

        first = runs[0] if runs else None
        coverage = 0.0
        if first is not None:
            match = _COVERAGE.search(first.stdout)
            coverage = float(match.group(1)) if match else 0.0
        if coverage == 0.0:
            coverage = report.coverage_percent
        coverage_diagnostic = ""
        if first is None:
            coverage_diagnostic = "coverage was not measured: pytest did not produce a report"
        elif "was never imported" in first.stderr or "No data was collected" in first.stderr:
            coverage_diagnostic = (
                "coverage target was not exercised: " + first.stderr.strip()[-4000:]
            )
        elif _COVERAGE.search(first.stdout) is None:
            coverage_diagnostic = "coverage report was not generated"
            details = "\n".join(part for part in (first.stdout, first.stderr) if part)
            if details:
                coverage_diagnostic += f": {details[-4000:]}"

        conditions.append(
            AcceptanceCondition(
                name="tests_pass",
                passed=report.exit_code == 0 and report.tests_failed == 0,
                detail=(
                    f"{report.tests_passed} passed, {report.tests_failed} failed "
                    f"(exit code {report.exit_code})"
                ),
            )
        )
        conditions.append(
            AcceptanceCondition(
                name="mypy_strict_clean",
                passed=mypy_clean,
                detail=(
                    "mypy --strict reported no error"
                    if mypy_clean
                    else "mypy --strict failed: " + (mypy_output or "no diagnostics captured")
                ),
            )
        )
        conditions.append(
            AcceptanceCondition(
                name="coverage_target",
                passed=coverage >= self.coverage_target and not coverage_diagnostic,
                detail=(
                    f"coverage {coverage:.2f}% against a target of {self.coverage_target:.0f}%"
                    + (f"; {coverage_diagnostic}" if coverage_diagnostic else "")
                ),
            )
        )
        blocking = [finding for finding in security.security_findings if finding.blocking]
        conditions.append(
            AcceptanceCondition(
                name="security_clean",
                passed=not blocking,
                detail=(
                    "no high or critical finding"
                    if not blocking
                    else f"{len(blocking)} blocking finding(s): "
                    + ", ".join(f"{item.rule} {item.file}:{item.line}" for item in blocking[:5])
                ),
            )
        )
        missing = self._uncovered(spec, suite)
        conditions.append(
            AcceptanceCondition(
                name="requirements_covered",
                passed=not missing and report.tests_failed == 0,
                detail=(
                    "every requirement has a passing test"
                    if not missing and report.tests_failed == 0
                    else (
                        f"{report.tests_failed} test(s) failed or could not be collected"
                        if not missing
                        else "no passing test for: " + ", ".join(missing)
                    )
                ),
            )
        )
        conditions.append(
            AcceptanceCondition(
                name="deterministic",
                passed=self._deterministic(runs),
                detail=(
                    "two runs of the suite produced the same result"
                    if self._deterministic(runs)
                    else "the two runs of the suite disagreed"
                ),
            )
        )

        assessment = self._classify(spec, workspace)
        approval_id: str | None = None
        if assessment.tier.at_least(RiskTier.HIGH):
            approval_id = self._request_approval(
                run_id=run_id,
                tenant_id=tenant_id,
                tier=assessment.tier,
                signals=list(assessment.signals),
            )
        conditions.append(
            AcceptanceCondition(
                name="human_approval_for_high_risk",
                passed=True,
                detail=(
                    "the task is not high risk"
                    if approval_id is None
                    else f"the task is high risk and needs the approval {approval_id}"
                ),
            )
        )

        result = AcceptanceResult(
            conditions=conditions,
            risk_tier=assessment.tier,
            approval_id=approval_id,
        )
        acceptance_report = ExecutionReport(
            run_id=f"acceptance-{report.run_id}",
            requirement_id=report.requirement_id,
            command="acceptance_gate",
            exit_code=0 if result.passed else 1,
            tests_passed=report.tests_passed,
            tests_failed=report.tests_failed,
            coverage_percent=coverage,
            mypy_clean=mypy_clean,
            mypy_output=mypy_output,
            coverage_diagnostic=coverage_diagnostic,
            security_events=list(report.security_events),
            security_findings=list(security.security_findings),
            risk_tier=assessment.tier,
            risk_signals=list(assessment.signals),
            acceptance=result,
            deterministic=self._deterministic(runs),
            workspace_mount=report.workspace_mount,
            writable_paths=list(report.writable_paths),
            workspace_path=report.workspace_path,
        )
        if self.conversations is not None and not result.passed:
            failures = [
                condition.model_dump(mode="json")
                for condition in result.conditions
                if not condition.passed
            ]
            self.conversations.store(
                tenant_id=tenant_id,
                role="quality_gate",
                model="acceptance-gate",
                run_id=run_id,
                attempt=1,
                prompt=json.dumps(
                    {"run_id": run_id, "targets": targets}, sort_keys=True
                ),
                response=json.dumps(failures, sort_keys=True),
                error_type="quality_gate_failure",
                error=json.dumps(failures, sort_keys=True),
                metadata={
                    "failure_kind": "quality_gate",
                    "attempted_repairs": 0,
                    "agents": [],
                    "outcome": "failed",
                },
            )
        return acceptance_report

    async def _determinism_runs(
        self, workspace: Path | None, targets: list[str]
    ) -> list[Any]:
        """Run the suite twice and return both outcomes."""
        if workspace is None or not await asyncio.to_thread(workspace.is_dir):
            return []
        command = self.sandbox.pytest_command(targets)
        return await self.sandbox.run_in_directory(
            directory=workspace,
            commands=[command, command],
        )

    async def _mypy_result(
        self, workspace: Path | None, targets: list[str]
    ) -> CommandResult | None:
        """Return the full strict type-check result for diagnosis and repair."""
        if workspace is None or not targets:
            return None
        if not await asyncio.to_thread(workspace.is_dir):
            return None
        results = await self.sandbox.run_in_directory(
            directory=workspace,
            commands=[self.sandbox.mypy_command(targets)],
        )
        return results[0] if results else None

    def _deterministic(self, runs: list[Any]) -> bool:
        """Two runs agree when they fail the same way and pass the same tests."""
        if len(runs) < 2:
            return False
        first, second = runs[0], runs[1]
        if first.exit_code != second.exit_code:
            return False
        return self._outcomes(first.stdout) == self._outcomes(second.stdout)

    def _outcomes(self, stdout: str) -> list[tuple[str, str]]:
        return sorted(_RESULT_LINE.findall(stdout))

    def _uncovered(self, spec: RequirementSpec | None, suite: TestSuite) -> list[str]:
        if spec is None:
            return []
        covered = suite.covered_requirement_ids()
        required = {spec.requirement_id}
        return sorted(required - covered)

    def _classify(self, spec: RequirementSpec | None, workspace: Path | None) -> RiskAssessment:
        files = self._sources(workspace)
        return self.classifier.classify(
            spec, files=files, declared_tier=self.declared_tier
        )

    def _sources(self, workspace: Path | None) -> dict[str, str]:
        """The generated code of the run, for the AST re-check of the risk."""
        if workspace is None or not workspace.is_dir():
            return {}
        sources: dict[str, str] = {}
        for path in sorted(workspace.rglob("*.py")):
            if "tests" in path.parts:
                continue
            try:
                sources[str(path.relative_to(workspace))] = path.read_text(
                    encoding="utf-8", errors="replace"
                )
            except OSError:
                continue
        return sources

    def _request_approval(
        self,
        *,
        run_id: str,
        tenant_id: str,
        tier: RiskTier,
        signals: list[str],
    ) -> str:
        gate = GateSpec(gate_id="risk_tier", type="risk_tier", params={"min_approval": "high"})
        request = self.approvals.request(
            run_id=run_id,
            tenant_id=tenant_id,
            gate=gate,
            artifact_type="risk_assessment",
            artifact={"risk_tier": tier.value, "signals": signals},
        )
        return request.approval_id


@dataclass
class RiskTierGate:
    """Holds a high risk task until an administrator decided."""

    approvals: ApprovalService

    async def evaluate(self, gate: GateSpec, context: dict[str, Any]) -> GateOutcome:
        outputs = context.get("outputs", {})
        artifact = outputs.get(str(gate.params.get("artifact", "acceptance_gate")))
        acceptance = getattr(artifact, "acceptance", None)
        if acceptance is None:
            return GateOutcome(
                status="failed",
                detail=f"gate '{gate.gate_id}' found no risk assessment",
            )
        required = RiskTier(str(gate.params.get("min_approval", "high")))
        if not acceptance.risk_tier.at_least(required):
            return GateOutcome(
                status="passed",
                detail=f"the risk tier is '{acceptance.risk_tier.value}'",
            )
        if not acceptance.approval_id:
            return GateOutcome(
                status="failed",
                detail=(
                    f"the task is '{acceptance.risk_tier.value}' risk "
                    "but no approval was requested"
                ),
            )
        request = self.approvals.get(acceptance.approval_id)
        if request is None:
            return GateOutcome(
                status="failed",
                detail=f"the approval request '{acceptance.approval_id}' is unknown",
            )
        run_id = str(context.get("run_id", ""))
        tenant_id = str(context.get("tenant_id", ""))
        if run_id and request.run_id != run_id:
            return GateOutcome(
                status="failed",
                detail=(
                    f"approval '{request.approval_id}' belongs to run '{request.run_id}', "
                    f"not the active run '{run_id}'"
                ),
                data={"approval_id": request.approval_id},
            )
        if tenant_id and request.tenant_id and request.tenant_id != tenant_id:
            return GateOutcome(
                status="failed",
                detail=f"approval '{request.approval_id}' belongs to another tenant",
                data={"approval_id": request.approval_id},
            )
        if request.status == "pending":
            return GateOutcome(
                status="pending_approval",
                detail=f"waiting for the approval of the high risk task ({request.approval_id})",
                data={"approval_id": request.approval_id},
            )
        if request.status == "approved":
            return GateOutcome(
                status="passed",
                detail=f"the high risk task was approved by {request.decided_by}",
                data={"approval_id": request.approval_id},
            )
        return GateOutcome(
            status="failed",
            detail=request.note or f"the high risk task was rejected by {request.decided_by}",
            data={"approval_id": request.approval_id},
        )


@dataclass
class AcceptanceGate:
    """Fails the run when an acceptance condition did not pass."""

    async def evaluate(self, gate: GateSpec, context: dict[str, Any]) -> GateOutcome:
        outputs = context.get("outputs", {})
        artifact = outputs.get(str(gate.params.get("artifact", "acceptance_gate")))
        result = getattr(artifact, "acceptance", None)
        if result is None:
            return GateOutcome(
                status="failed",
                detail=f"gate '{gate.gate_id}' found no acceptance result",
            )
        failures = result.failures()
        if not failures:
            return GateOutcome(status="passed", detail="every acceptance condition passed")
        detail = ", ".join(f"{item.name}: {item.detail}" for item in failures)
        return GateOutcome(
            status="failed",
            detail=f"{len(failures)} acceptance condition(s) failed: {detail}",
        )


@dataclass
class SecurityCleanGate:
    """Fails the run when the security report holds a blocking finding."""

    async def evaluate(self, gate: GateSpec, context: dict[str, Any]) -> GateOutcome:
        outputs = context.get("outputs", {})
        artifact = outputs.get(str(gate.params.get("artifact", "security_gate")))
        findings = getattr(artifact, "security_findings", None) or []
        blocking = [finding for finding in findings if finding.blocking]
        if not blocking:
            return GateOutcome(status="passed", detail="the security report is clean")
        detail = "; ".join(
            f"{finding.rule} ({finding.severity}) {finding.file}:{finding.line}: "
            f"{finding.message}"
            for finding in blocking
        )
        attempts = str(getattr(artifact, "stderr", "") or "")
        report = f"{len(blocking)} blocking security finding(s): {detail}"
        if attempts:
            report += f"\n{attempts}"
        return GateOutcome(status="failed", detail=report)


def _classifier(policy: AstPolicy | None = None) -> RiskClassifier:
    return RiskClassifier(policy) if policy is not None else RiskClassifier()
