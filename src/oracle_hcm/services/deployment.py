"""The SOP step that deploys a verified artifact.

The step verifies the artifact before it deploys it: a single mismatch
refuses the deployment and the refusal is written to the audit log.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from oracle_hcm.deploy.service import DeploymentRequest, DeploymentService
from oracle_hcm.knowledge.memory import DeploymentMemory, MemoryWriter
from oracle_hcm.schemas.artifacts import DeploymentOutcome, ExecutionReport, RequirementSpec
from oracle_hcm.signing.service import load_signed_manifest
from oracle_hcm.sop.engine import GateOutcome
from oracle_hcm.sop.models import GateSpec

__all__ = ["DeploymentGate", "DeploymentStep"]


@dataclass
class DeploymentStep:
    """Deploys the artifact of a signed run behind the router."""

    service: DeploymentService
    memory: MemoryWriter | None = None

    async def __call__(self, payload: dict[str, Any]) -> ExecutionReport:
        """Verify the signed artifact and roll it out."""
        report = ExecutionReport.model_validate(payload.get("report", {}))
        manifest_path = report.manifest_path
        if not manifest_path:
            raise FileNotFoundError("the step runs without a signed manifest")
        signed = load_signed_manifest(Path(manifest_path).parent)
        request = DeploymentRequest(
            signed=signed,
            workspace=Path(report.workspace_path),
            tenant_id=str(payload.get("tenant_id", "default")),
            run_id=str(payload.get("run_id", "")),
        )
        outcome = await self.service.deploy(request)
        if self.memory is not None and outcome.status == "deployed":
            self.memory.record(
                signed=signed,
                memory=self._memory_of(payload, outcome),
                workspace=Path(report.workspace_path),
                spec=self._spec_of(payload),
            )
        return ExecutionReport(
            run_id=f"deploy-{report.run_id}",
            requirement_id=report.requirement_id,
            command="deploy",
            exit_code=0 if outcome.status == "deployed" else 1,
            risk_tier=report.risk_tier,
            workspace_path=report.workspace_path,
            artifact_id=outcome.artifact_id,
            manifest_path=manifest_path,
            deployment=outcome,
        )

    def _spec_of(self, payload: dict[str, Any]) -> RequirementSpec | None:
        """The specification of the run, when the step carries one."""
        raw = payload.get("spec")
        if not raw:
            return None
        return RequirementSpec.model_validate(raw)

    def _memory_of(
        self, payload: dict[str, Any], outcome: DeploymentOutcome
    ) -> DeploymentMemory:
        """What the deployment learned."""
        spec = self._spec_of(payload)
        run = ExecutionReport.model_validate(payload.get("run", {}))
        worked = (
            f"the sandbox run passed {run.tests_passed} tests "
            f"with {run.coverage_percent}% coverage"
        )
        failed = (
            f"the run reported {run.tests_failed} failing tests"
            if run.tests_failed
            else "nothing failed during the run"
        )
        return DeploymentMemory(
            tenant_id=str(payload.get("tenant_id", "default")),
            run_id=str(payload.get("run_id", "")),
            artifact_hash=outcome.root_hash,
            requirement_id=spec.requirement_id if spec is not None else "",
            task_type=spec.task_type if spec is not None else "feature",
            worked=worked,
            failed=failed,
        )


@dataclass
class DeploymentGate:
    """Fails the run when the deployment did not reach the traffic."""

    async def evaluate(self, gate: GateSpec, context: dict[str, Any]) -> GateOutcome:
        outputs = context.get("outputs", {})
        artifact = outputs.get(str(gate.params.get("artifact", "deploy")))
        outcome = getattr(artifact, "deployment", None)
        if outcome is None:
            return GateOutcome(
                status="failed",
                detail=f"gate '{gate.gate_id}' found no deployment outcome",
            )
        if outcome.status == "deployed":
            return GateOutcome(
                status="passed",
                detail=f"version '{outcome.version}' carries the traffic",
            )
        reason = outcome.rollback_reason or f"the deployment was '{outcome.status}'"
        return GateOutcome(status="failed", detail=reason)
