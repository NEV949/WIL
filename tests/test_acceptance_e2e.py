"""End to end acceptance.

One task passes every acceptance condition and one is blocked. Everything runs
for real: the suite, the scanners and the type checker run in the sandbox image
with the same hardening as a production run, and the acceptance gate runs the
suite twice on its own to decide whether the result is deterministic.
"""

from __future__ import annotations

import pytest

from acceptance_tasks import outcomes, root_directory
from oracle_hcm.schemas.artifacts import RiskTier
from oracle_hcm.services.acceptance import AcceptanceGate, RiskTierGate
from oracle_hcm.services.approvals import ApprovalService
from oracle_hcm.sop.models import GateSpec
from security_attacks import docker_is_ready

pytestmark = [
    pytest.mark.docker,
    pytest.mark.skipif(not docker_is_ready(), reason="the docker daemon does not answer"),
]


async def test_a_clean_task_passes_every_acceptance_condition() -> None:
    outcome = (await outcomes())["passing"]

    assert outcome.run.exit_code == 0, outcome.run.stdout
    assert outcome.run.tests_passed == 1
    assert outcome.run.tests_failed == 0
    assert outcome.run.coverage_percent >= 80.0
    assert not [item for item in outcome.security.security_findings if item.blocking]

    result = outcome.acceptance.acceptance
    assert result is not None
    assert result.passed is True
    assert result.failures() == []
    assert len(result.conditions) == 7
    assert result.risk_tier is RiskTier.LOW

    gate = await AcceptanceGate().evaluate(
        GateSpec(
            gate_id="acceptance_passed",
            type="acceptance",
            params={"artifact": "acceptance_gate"},
        ),
        {"outputs": {"acceptance_gate": outcome.acceptance}},
    )
    assert gate.status == "passed", gate.detail


async def test_a_broken_task_is_blocked_with_a_reason_per_condition() -> None:
    outcome = (await outcomes())["blocked"]

    result = outcome.acceptance.acceptance
    assert result is not None
    assert result.passed is False

    conditions = outcome.conditions
    assert conditions["tests_pass"].passed is False
    assert conditions["mypy_strict_clean"].passed is False
    assert conditions["coverage_target"].passed is False
    assert conditions["requirements_covered"].passed is False
    assert conditions["security_clean"].passed is True
    assert conditions["deterministic"].passed is True
    assert conditions["human_approval_for_high_risk"].passed is True

    gate = await AcceptanceGate().evaluate(
        GateSpec(
            gate_id="acceptance_passed",
            type="acceptance",
            params={"artifact": "acceptance_gate"},
        ),
        {"outputs": {"acceptance_gate": outcome.acceptance}},
    )
    assert gate.status == "failed"
    assert "tests_pass" in gate.detail
    assert "mypy_strict_clean" in gate.detail


async def test_a_low_risk_task_does_not_ask_for_an_approval() -> None:
    outcome = (await outcomes())["passing"]
    approvals = ApprovalService(root_directory() / "approvals")

    result = outcome.acceptance.acceptance
    assert result is not None
    assert result.approval_id is None
    assert approvals.pending() == []

    gate = await RiskTierGate(approvals).evaluate(
        GateSpec(
            gate_id="risk_tier",
            type="risk_tier",
            params={"artifact": "acceptance_gate", "min_approval": "high"},
        ),
        {"outputs": {"acceptance_gate": outcome.acceptance}},
    )
    assert gate.status == "passed", gate.detail
