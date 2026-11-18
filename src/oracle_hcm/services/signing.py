"""The SOP step that signs an accepted artifact.

The step runs on the host. The private key stays inside the signing package:
the agent that produced the code, the sandbox and the audit log never see it.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from oracle_hcm.schemas.artifacts import ExecutionReport, RequirementSpec
from oracle_hcm.services.approvals import ApprovalService
from oracle_hcm.signing.manifest import ApprovalPin
from oracle_hcm.signing.service import MANIFEST_NAME, SIGNATURE_NAME, ArtifactSigner, report_hash

__all__ = ["SigningStep"]


@dataclass
class SigningStep:
    """Builds the manifest of an accepted artifact and signs its root hash."""

    signer: ArtifactSigner
    approvals: ApprovalService

    async def __call__(self, payload: dict[str, Any]) -> ExecutionReport:
        """Sign the artifact of an accepted run."""
        report = ExecutionReport.model_validate(payload.get("report", {}))
        security = ExecutionReport.model_validate(payload.get("security", {}))
        acceptance = ExecutionReport.model_validate(payload.get("acceptance", {}))
        spec = RequirementSpec.model_validate(payload.get("spec", {}))
        run_id = str(payload.get("run_id", ""))
        tenant_id = str(payload.get("tenant_id", "default"))
        workspace = Path(report.workspace_path)
        if not await asyncio.to_thread(workspace.is_dir):
            raise FileNotFoundError(f"the workspace of the run is missing: {workspace}")

        artifact_id = f"{run_id or 'run'}-{spec.requirement_id}"
        result = acceptance.acceptance
        self.signer.sign_artifact(
            artifact_id=artifact_id,
            requirement_id=spec.requirement_id,
            workspace=workspace,
            test_report=report,
            security_report=security,
            acceptance_result=result,
            risk_tier=acceptance.risk_tier.value,
            approvals=self._approval_pins(run_id),
            tenant_id=tenant_id,
            run_id=run_id,
        )
        directory = self.signer.artifact_directory(artifact_id)
        return ExecutionReport(
            run_id=f"sign-{report.run_id}",
            requirement_id=spec.requirement_id,
            command="sign",
            exit_code=0,
            coverage_percent=report.coverage_percent,
            risk_tier=acceptance.risk_tier,
            risk_signals=list(acceptance.risk_signals),
            workspace_path=report.workspace_path,
            artifact_id=artifact_id,
            manifest_path=str(directory / MANIFEST_NAME),
            produced_files=[str(directory / MANIFEST_NAME), str(directory / SIGNATURE_NAME)],
        )

    def _approval_pins(self, run_id: str) -> list[ApprovalPin]:
        """The hashes of the approvals that guarded the run."""
        pins: list[ApprovalPin] = []
        for request in self.approvals.for_run(run_id):
            pins.append(
                ApprovalPin(
                    gate_id=request.gate_id,
                    stage=request.stage,
                    approval_id=request.approval_id,
                    status=request.status,
                    sha256=report_hash(request.to_json()),
                )
            )
        return pins
