"""Orchestrator.

The orchestrator drives one SOP run: it assembles the agents, records every
step in the audit log, and hands the run to the engine. When the engine stops
at an administrator approval the run state is written to disk so that the run
can be resumed once the decision has been recorded.
"""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from pydantic import BaseModel

from oracle_hcm.errors import RateLimitError
from oracle_hcm.knowledge.retrieval import RetrievalService
from oracle_hcm.log.eventlog import EventLog
from oracle_hcm.paths import data_dir, keys_dir
from oracle_hcm.schemas.artifacts import ExecutionReport, RiskTier
from oracle_hcm.services.approvals import ApprovalRequest, ApprovalService
from oracle_hcm.sop.engine import SopEngine, SopResume, SopRunResult, StepResult
from oracle_hcm.sop.models import SopDefinition

__all__ = ["OrchestrationResult", "Orchestrator", "RunState"]


@dataclass
class RunState:
    """State of a run, persisted so it survives a restart."""

    run_id: str
    sop_id: str
    tenant_id: str
    request: str
    status: str
    step_index: int = 0
    suspended_step: str | None = None
    outputs: dict[str, dict[str, Any]] = field(default_factory=dict)
    approval_id: str | None = None

    def to_json(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "sop_id": self.sop_id,
            "tenant_id": self.tenant_id,
            "request": self.request,
            "status": self.status,
            "step_index": self.step_index,
            "suspended_step": self.suspended_step,
            "outputs": self.outputs,
            "approval_id": self.approval_id,
        }

    @classmethod
    def from_json(cls, data: dict[str, Any]) -> RunState:
        return cls(
            run_id=data["run_id"],
            sop_id=data["sop_id"],
            tenant_id=data["tenant_id"],
            request=data["request"],
            status=data["status"],
            step_index=int(data.get("step_index", 0)),
            suspended_step=data.get("suspended_step"),
            outputs=data.get("outputs", {}),
            approval_id=data.get("approval_id"),
        )


@dataclass
class OrchestrationResult:
    """What the orchestrator reports back to its caller."""

    run_id: str
    status: str
    sop_result: SopRunResult | None = None
    approval: ApprovalRequest | None = None
    report: ExecutionReport | None = None
    failure: str | None = None

    @property
    def completed(self) -> bool:
        return self.status == "completed"


class Orchestrator:
    """Runs one SOP end to end."""

    def __init__(
        self,
        *,
        engine: SopEngine,
        sop: SopDefinition,
        approvals: ApprovalService,
        event_log: EventLog,
        schemas: dict[str, type[BaseModel]],
        state_directory: Path | None = None,
        max_phase: int = 3,
        retrieval: RetrievalService | None = None,
        artifact_root: Path | None = None,
        keys_directory: Path | None = None,
    ) -> None:
        self._engine = engine
        self._sop = sop
        self._approvals = approvals
        self._log = event_log
        self._schemas = schemas
        self._state_directory = (
            state_directory if state_directory is not None else data_dir() / "runs"
        )
        self._max_phase = max_phase
        self._retrieval = retrieval
        self._artifact_root = (
            artifact_root if artifact_root is not None else data_dir() / "artifacts"
        )
        self._keys_directory = keys_directory if keys_directory is not None else keys_dir()

    @property
    def state_directory(self) -> Path:
        """Where the state of the runs is kept."""
        return self._state_directory

    @property
    def artifact_root(self) -> Path:
        """Where the manifests of the signed artifacts are kept."""
        return self._artifact_root

    @property
    def keys_directory(self) -> Path:
        """Where the signing key of the host is kept."""
        return self._keys_directory

    def _state_path(self, run_id: str) -> Path:
        return self._state_directory / f"{run_id}.json"

    def _write_state(self, state: RunState) -> None:
        self._state_directory.mkdir(parents=True, exist_ok=True)
        self._state_path(state.run_id).write_text(
            json.dumps(state.to_json(), indent=2, ensure_ascii=False),
            encoding="utf-8",
        )

    def _read_state(self, run_id: str) -> RunState:
        path = self._state_path(run_id)
        if not path.is_file():
            raise FileNotFoundError(f"unknown run '{run_id}'")
        return RunState.from_json(json.loads(path.read_text(encoding="utf-8")))

    def _rehydrate(self, state: RunState) -> dict[str, BaseModel]:
        outputs: dict[str, BaseModel] = {}
        schemas_by_step = {step.step_id: step.output_schema for step in self._sop.steps}
        for step_id, payload in state.outputs.items():
            schema_name = schemas_by_step.get(step_id)
            if schema_name is None:
                continue
            schema = self._schemas.get(schema_name)
            if schema is None:
                continue
            outputs[step_id] = schema.model_validate(payload)
        return outputs

    def _audit_step(self, tenant_id: str, run_id: str, result: SopRunResult) -> None:
        for step in result.steps:
            self._log.append(
                tenant_id=tenant_id,
                actor="orchestrator",
                action="step_completed",
                payload={
                    "run_id": run_id,
                    "step_id": step.step_id,
                    "agent": step.agent,
                    "attempts": step.attempts,
                    "output_type": type(step.output).__name__,
                },
            )
            self._audit_risk(tenant_id, run_id, step)

    def _audit_risk(self, tenant_id: str, run_id: str, step: StepResult) -> None:
        """Record the risk tier of a step and the signals that produced it."""
        output = step.output
        if not isinstance(output, ExecutionReport):
            return
        if output.risk_tier is RiskTier.LOW and not output.risk_signals:
            return
        self._log.append(
            tenant_id=tenant_id,
            actor="orchestrator",
            action="risk_assessed",
            payload={
                "run_id": run_id,
                "step_id": step.step_id,
                "risk_tier": output.risk_tier.value,
                "risk_signals": list(output.risk_signals),
            },
        )

    def _approval_for(self, result: SopRunResult) -> ApprovalRequest | None:
        if result.pending_outcome is None:
            return None
        approval_id = result.pending_outcome.data.get("approval_id")
        if not approval_id:
            return None
        return self._approvals.get(approval_id)

    async def run(
        self,
        request: str,
        *,
        tenant_id: str = "default",
        run_id: str | None = None,
    ) -> OrchestrationResult:
        """Start a new run and stop at the first approval.

        The caller may name the run, so that it can address the run it has
        just started. Without a name the run gets one of its own.
        """
        run_id = run_id or uuid.uuid4().hex[:12]
        self._log.append(
            tenant_id=tenant_id,
            actor="orchestrator",
            action="run_started",
            payload={"run_id": run_id, "sop_id": self._sop.sop_id},
        )
        try:
            result = await self._engine.run(
                self._sop,
                {
                    "request": request,
                    "run_id": run_id,
                    "repo_context": "",
                    "tenant_id": tenant_id,
                },
                max_phase=self._max_phase,
            )
        except RateLimitError as exc:
            self._log.append(
                tenant_id=tenant_id,
                actor="orchestrator",
                action="token_cap_exceeded",
                payload={"run_id": run_id, "error": str(exc)},
            )
            raise
        return self._finish(run_id, tenant_id, request, result)

    async def resume(self, run_id: str) -> OrchestrationResult:
        """Continue a run that stopped at an approval."""
        state = self._read_state(run_id)
        approval = self._approvals.get(state.approval_id) if state.approval_id else None
        if approval is None:
            raise FileNotFoundError(f"run '{run_id}' has no approval to resume")
        if approval.status == "pending":
            raise ValueError(f"approval '{approval.approval_id}' is still pending")
        outputs = self._rehydrate(state)
        if approval.artifact_type == "tests" and self._retrieval is not None:
            self._retrieval.freeze_suite(run_id)
        resume = SopResume(
            index=state.step_index,
            outputs=outputs,
            results=[],
            pending_result=self._pending_result(state, outputs),
        )
        self._log.append(
            tenant_id=state.tenant_id,
            actor="orchestrator",
            action="run_resumed",
            payload={"run_id": run_id, "approval_id": approval.approval_id},
        )
        try:
            result = await self._engine.run(
                self._sop,
                {
                    "request": state.request,
                    "run_id": run_id,
                    "repo_context": "",
                    "tenant_id": state.tenant_id,
                },
                max_phase=self._max_phase,
                resume=resume,
            )
        except RateLimitError as exc:
            self._log.append(
                tenant_id=state.tenant_id,
                actor="orchestrator",
                action="token_cap_exceeded",
                payload={"run_id": run_id, "error": str(exc)},
            )
            raise
        return self._finish(run_id, state.tenant_id, state.request, result)

    def _pending_result(self, state: RunState, outputs: dict[str, BaseModel]) -> StepResult:
        if not state.suspended_step or state.suspended_step not in outputs:
            raise ValueError(f"run '{state.run_id}' has no suspended step")
        return StepResult(
            step_id=state.suspended_step,
            agent="orchestrator",
            output=outputs[state.suspended_step],
            attempts=1,
        )

    def _finish(
        self,
        run_id: str,
        tenant_id: str,
        request: str,
        result: SopRunResult,
    ) -> OrchestrationResult:
        self._audit_step(tenant_id, run_id, result)
        state = RunState(
            run_id=run_id,
            sop_id=self._sop.sop_id,
            tenant_id=tenant_id,
            request=request,
            status=result.status,
            step_index=self._suspended_index(result),
            outputs={
                step_id: output.model_dump(mode="json")
                for step_id, output in result.outputs.items()
            },
        )
        approval = self._approval_for(result)
        if approval is not None:
            state.approval_id = approval.approval_id
            state.suspended_step = self._suspended_step_id(result)
            self._log.append(
                tenant_id=tenant_id,
                actor="orchestrator",
                action="approval_requested",
                payload={
                    "run_id": run_id,
                    "approval_id": approval.approval_id,
                    "gate_id": approval.gate_id,
                    "stage": approval.stage,
                    "artifact_type": approval.artifact_type,
                },
            )
            self._write_state(state)
            return OrchestrationResult(
                run_id=run_id,
                status="awaiting_approval",
                sop_result=result,
                approval=approval,
            )
        self._write_state(state)
        report = result.outputs.get("sandbox_run")
        self._log.append(
            tenant_id=tenant_id,
            actor="orchestrator",
            action="run_completed" if result.status == "completed" else "run_failed",
            payload={
                "run_id": run_id,
                "status": result.status,
                "failure": result.failure,
            },
        )
        return OrchestrationResult(
            run_id=run_id,
            status=result.status,
            sop_result=result,
            report=report if isinstance(report, ExecutionReport) else None,
            failure=result.failure,
        )

    def _suspended_index(self, result: SopRunResult) -> int:
        for index, step in enumerate(self._sop.steps):
            if result.pending_gate is not None and step.gates:
                for gate in step.gates:
                    if gate.gate_id == result.pending_gate.gate_id:
                        return index
        return 0

    def _suspended_step_id(self, result: SopRunResult) -> str:
        if result.pending_gate is None:
            return ""
        for step in self._sop.steps:
            for gate in step.gates:
                if gate.gate_id == result.pending_gate.gate_id:
                    return step.step_id
        return ""
