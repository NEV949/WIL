"""Administrator approvals."""

from __future__ import annotations

from pathlib import Path

import pytest

from oracle_hcm.schemas.artifacts import RequirementSpec
from oracle_hcm.services.approvals import (
    AdminApprovalGate,
    ApprovalError,
    ApprovalService,
    approval_identifier,
)
from oracle_hcm.sop.models import GateSpec


def _gate(stage: int = 1, artifact: str = "requirements") -> GateSpec:
    return GateSpec(
        gate_id="approval_spec",
        type="admin_approval",
        params={"stage": stage, "artifact": artifact},
    )


def _spec() -> RequirementSpec:
    return RequirementSpec(
        requirement_id="REQ-1",
        title="Add overtime",
        description="Overtime pay.",
        acceptance_criteria=["Overtime is paid at 1.5x."],
    )


def test_the_identifier_is_stable(tmp_path: Path) -> None:
    service = ApprovalService(tmp_path)
    first = service.request(
        run_id="run-1",
        gate=_gate(),
        artifact_type="requirements",
        artifact=_spec().model_dump(mode="json"),
    )
    second = service.request(
        run_id="run-1",
        gate=_gate(),
        artifact_type="requirements",
        artifact=_spec().model_dump(mode="json"),
    )
    assert first.approval_id == second.approval_id
    assert first.approval_id == approval_identifier(
        "run-1", "approval_spec", _spec().model_dump(mode="json")
    )
    assert len(list(tmp_path.glob("*.json"))) == 1


def test_pending_approval_creation_is_persisted_with_run_and_tenant(tmp_path: Path) -> None:
    service = ApprovalService(tmp_path)

    request = service.request(
        run_id="run-1",
        tenant_id="tenant-1",
        gate=_gate(),
        artifact_type="risk_assessment",
        artifact={"risk_tier": "high", "signals": ["payroll"]},
    )
    reopened = ApprovalService(tmp_path).get(request.approval_id)

    assert reopened is not None
    assert reopened.status == "pending"
    assert reopened.run_id == "run-1"
    assert reopened.tenant_id == "tenant-1"
    assert reopened.gate_id == "approval_spec"
    assert reopened.stage == 1
    assert reopened.artifact_type == "risk_assessment"


def test_a_request_is_pending_until_it_is_decided(tmp_path: Path) -> None:
    service = ApprovalService(tmp_path)
    request = service.request(
        run_id="run-1",
        gate=_gate(),
        artifact_type="requirements",
        artifact=_spec().model_dump(mode="json"),
    )
    assert request.status == "pending"
    assert request.stage == 1
    assert service.pending() == [request]


def test_a_decision_is_persisted(tmp_path: Path) -> None:
    service = ApprovalService(tmp_path)
    request = service.request(
        run_id="run-1",
        gate=_gate(),
        artifact_type="requirements",
        artifact=_spec().model_dump(mode="json"),
    )
    decided = service.decide(request.approval_id, approved=True, decided_by="jo")
    assert decided.status == "approved"
    assert decided.decided_by == "jo"
    assert decided.decided_at is not None
    stored = ApprovalService(tmp_path).get(request.approval_id)
    assert stored is not None
    assert stored.status == "approved"
    assert service.pending() == []


def test_a_request_cannot_be_decided_twice(tmp_path: Path) -> None:
    service = ApprovalService(tmp_path)
    request = service.request(
        run_id="run-1",
        gate=_gate(),
        artifact_type="requirements",
        artifact=_spec().model_dump(mode="json"),
    )
    service.decide(request.approval_id, approved=True)
    with pytest.raises(ApprovalError):
        service.decide(request.approval_id, approved=True)


def test_an_unknown_request_cannot_be_decided(tmp_path: Path) -> None:
    with pytest.raises(ApprovalError):
        ApprovalService(tmp_path).decide("nope", approved=True)


async def test_the_gate_holds_the_run_until_the_approval(tmp_path: Path) -> None:
    service = ApprovalService(tmp_path)
    gate = AdminApprovalGate(service)
    context = {"run_id": "run-1", "tenant_id": "tenant-1", "outputs": {"requirements": _spec()}}

    outcome = await gate.evaluate(_gate(), context)

    assert outcome.status == "pending_approval"
    assert outcome.data["approval_id"]
    assert service.pending()[0].tenant_id == "tenant-1"


async def test_duplicate_gate_delivery_does_not_duplicate_a_pending_record(tmp_path: Path) -> None:
    service = ApprovalService(tmp_path)
    gate = AdminApprovalGate(service)
    context = {"run_id": "run-1", "outputs": {"requirements": _spec()}}

    first = await gate.evaluate(_gate(), context)
    duplicate = await gate.evaluate(_gate(), context)

    assert duplicate.data["approval_id"] == first.data["approval_id"]
    assert len(service.pending()) == 1


async def test_the_gate_passes_after_an_approval(tmp_path: Path) -> None:
    service = ApprovalService(tmp_path)
    gate = AdminApprovalGate(service)
    context = {"run_id": "run-1", "outputs": {"requirements": _spec()}}
    first = await gate.evaluate(_gate(), context)
    service.decide(first.data["approval_id"], approved=True, decided_by="jo")

    second = await gate.evaluate(_gate(), context)

    assert second.status == "passed"


async def test_a_rejection_fails_the_gate(tmp_path: Path) -> None:
    service = ApprovalService(tmp_path)
    gate = AdminApprovalGate(service)
    context = {"run_id": "run-1", "outputs": {"requirements": _spec()}}
    first = await gate.evaluate(_gate(), context)
    service.decide(first.data["approval_id"], approved=False, decided_by="jo", note="not this time")

    second = await gate.evaluate(_gate(), context)

    assert second.status == "failed"
    assert "not this time" in second.detail


async def test_a_gate_without_its_artifact_fails(tmp_path: Path) -> None:
    gate = AdminApprovalGate(ApprovalService(tmp_path))

    outcome = await gate.evaluate(_gate(), {"run_id": "run-1", "outputs": {}})

    assert outcome.status == "failed"
