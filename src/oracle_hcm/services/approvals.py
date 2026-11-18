"""Administrator approvals.

Two approvals guard a run: the specification is approved before any code is
written, and the test suite is approved before the code is executed. An
approval request is a file on disk so that an administrator can decide from
another process, and so that the decision survives a restart.
"""

from __future__ import annotations

import hashlib
import json
import threading
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any, Literal

from oracle_hcm.canonical import canonical_bytes
from oracle_hcm.errors import OracleHcmError
from oracle_hcm.paths import data_dir
from oracle_hcm.schemas.artifacts import utc_now_iso
from oracle_hcm.sop.engine import GateOutcome
from oracle_hcm.sop.models import GateSpec

__all__ = [
    "AdminApprovalGate",
    "ApprovalError",
    "ApprovalRequest",
    "ApprovalService",
]

ApprovalStatus = Literal["pending", "approved", "rejected"]


class ApprovalError(OracleHcmError):
    """An approval request is unknown or already decided."""


@dataclass(frozen=True)
class ApprovalRequest:
    """One approval waiting for, or carrying, a decision."""

    approval_id: str
    run_id: str
    gate_id: str
    stage: int
    artifact_type: str
    artifact: dict[str, Any] = field(default_factory=dict)
    tenant_id: str = ""
    requested_at: str = field(default_factory=utc_now_iso)
    status: ApprovalStatus = "pending"
    decided_at: str | None = None
    decided_by: str | None = None
    note: str = ""
    artifact_hash: str = ""
    """The hash of the exact artifact the decision was taken on."""

    def to_json(self) -> dict[str, Any]:
        return {
            "approval_id": self.approval_id,
            "run_id": self.run_id,
            "gate_id": self.gate_id,
            "stage": self.stage,
            "artifact_type": self.artifact_type,
            "artifact": self.artifact,
            "tenant_id": self.tenant_id,
            "requested_at": self.requested_at,
            "status": self.status,
            "decided_at": self.decided_at,
            "decided_by": self.decided_by,
            "note": self.note,
            "artifact_hash": self.artifact_hash,
        }

    @classmethod
    def from_json(cls, data: dict[str, Any]) -> ApprovalRequest:
        return cls(
            approval_id=data["approval_id"],
            run_id=data["run_id"],
            gate_id=data["gate_id"],
            stage=int(data["stage"]),
            artifact_type=data["artifact_type"],
            artifact=data.get("artifact", {}),
            tenant_id=data.get("tenant_id", ""),
            requested_at=data["requested_at"],
            status=data["status"],
            decided_at=data.get("decided_at"),
            decided_by=data.get("decided_by"),
            note=data.get("note", ""),
            artifact_hash=data.get("artifact_hash", ""),
        )


def approval_identifier(run_id: str, gate_id: str, artifact: dict[str, Any]) -> str:
    """Stable identifier so the same gate never creates two requests."""
    digest = hashlib.sha256(canonical_bytes(artifact)).hexdigest()[:16]
    return f"{run_id}-{gate_id}-{digest}"


class ApprovalService:
    """Stores approval requests and their decisions on disk."""

    def __init__(self, directory: Path | None = None) -> None:
        self._directory = directory if directory is not None else data_dir() / "approvals"
        self._lock = threading.RLock()

    @property
    def directory(self) -> Path:
        return self._directory

    def _path(self, approval_id: str) -> Path:
        return self._directory / f"{approval_id}.json"

    def _write(self, request: ApprovalRequest) -> ApprovalRequest:
        with self._lock:
            self._directory.mkdir(parents=True, exist_ok=True)
            self._path(request.approval_id).write_text(
                json.dumps(request.to_json(), indent=2, ensure_ascii=False),
                encoding="utf-8",
            )
        return request

    def request(
        self,
        *,
        run_id: str,
        tenant_id: str = "",
        gate: GateSpec,
        artifact_type: str,
        artifact: dict[str, Any],
    ) -> ApprovalRequest:
        """Create the request, or return the one that already exists."""
        approval_id = approval_identifier(run_id, gate.gate_id, artifact)
        with self._lock:
            existing = self.get(approval_id)
            if existing is not None:
                return existing
            request = ApprovalRequest(
                approval_id=approval_id,
                run_id=run_id,
                gate_id=gate.gate_id,
                stage=int(gate.params.get("stage", 0)),
                artifact_type=artifact_type,
                artifact=artifact,
                tenant_id=tenant_id,
            )
            return self._write(request)

    def reassociate(self, approval_id: str, *, run_id: str, tenant_id: str) -> ApprovalRequest:
        """Repair a pending legacy record using its matching audit event."""
        with self._lock:
            request = self.get(approval_id)
            if request is None or request.status != "pending":
                raise ApprovalError("only a pending approval can be reassociated")
            if request.tenant_id and request.tenant_id != tenant_id:
                raise ApprovalError("approval tenant does not match its audit event")
            updated = replace(request, run_id=run_id, tenant_id=tenant_id)
            return self._write(updated)

    def get(self, approval_id: str) -> ApprovalRequest | None:
        path = self._path(approval_id)
        if not path.is_file():
            return None
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise ApprovalError(f"approval file is corrupt: {path}") from exc
        return ApprovalRequest.from_json(data)

    def decide(
        self,
        approval_id: str,
        *,
        approved: bool,
        decided_by: str = "admin",
        note: str = "",
        artifact_hash: str = "",
    ) -> ApprovalRequest:
        """Record the decision of an administrator."""
        request = self.get(approval_id)
        if request is None:
            raise ApprovalError(f"unknown approval request '{approval_id}'")
        if request.status != "pending":
            raise ApprovalError(f"approval '{approval_id}' was already {request.status}")
        decided = ApprovalRequest(
            approval_id=request.approval_id,
            run_id=request.run_id,
            gate_id=request.gate_id,
            stage=request.stage,
            artifact_type=request.artifact_type,
            artifact=request.artifact,
            tenant_id=request.tenant_id,
            requested_at=request.requested_at,
            status="approved" if approved else "rejected",
            decided_at=utc_now_iso(),
            decided_by=decided_by,
            note=note,
            artifact_hash=artifact_hash,
        )
        return self._write(decided)

    def pending(self) -> list[ApprovalRequest]:
        """Every request that is still waiting for a decision."""
        if not self._directory.is_dir():
            return []
        requests: list[ApprovalRequest] = []
        for path in sorted(self._directory.glob("*.json")):
            request = self.get(path.stem)
            if request is not None and request.status == "pending":
                requests.append(request)
        return requests

    def for_run(self, run_id: str) -> list[ApprovalRequest]:
        """Every request that belongs to one run, in the order of the stages."""
        if not self._directory.is_dir():
            return []
        requests: list[ApprovalRequest] = []
        for path in sorted(self._directory.glob("*.json")):
            request = self.get(path.stem)
            if request is not None and request.run_id == run_id:
                requests.append(request)
        return sorted(requests, key=lambda request: request.stage)


class AdminApprovalGate:
    """Gate that holds a run until an administrator decides."""

    def __init__(self, service: ApprovalService) -> None:
        self._service = service

    async def evaluate(self, gate: GateSpec, context: dict[str, Any]) -> GateOutcome:
        artifact_type = str(gate.params.get("artifact", ""))
        outputs = context.get("outputs", {})
        artifact = outputs.get(artifact_type)
        if artifact is None:
            return GateOutcome(
                status="failed",
                detail=f"gate '{gate.gate_id}' found no artifact '{artifact_type}'",
            )
        payload = (
            artifact.model_dump(mode="json")
            if hasattr(artifact, "model_dump")
            else dict(artifact)
        )
        request = self._service.request(
            run_id=str(context.get("run_id", "default")),
            tenant_id=str(context.get("tenant_id", "")),
            gate=gate,
            artifact_type=artifact_type,
            artifact=payload,
        )
        if request.status == "pending":
            return GateOutcome(
                status="pending_approval",
                detail=f"waiting for approval of '{artifact_type}' ({request.approval_id})",
                data={"approval_id": request.approval_id},
            )
        if request.status == "approved":
            return GateOutcome(
                status="passed",
                detail=f"'{artifact_type}' approved by {request.decided_by}",
                data={"approval_id": request.approval_id},
            )
        return GateOutcome(
            status="failed",
            detail=request.note or f"'{artifact_type}' was rejected by {request.decided_by}",
            data={"approval_id": request.approval_id},
        )
