"""End to end: one task from the request to the canary deployment.

The whole pipeline runs with the fake backend: the requirement, the code and
the tests come from the scripted payloads, the suite runs in the sandbox image,
the gates decide, the artifact is signed, verified and rolled out behind the
router.
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import Iterator
from pathlib import Path

import pytest

from deployment_scenarios import docker_is_ready
from oracle_hcm.app import AppConfig, build_orchestrator
from oracle_hcm.deploy.service import DeploymentConfig, DeploymentService
from oracle_hcm.log.eventlog import EventLog
from oracle_hcm.schemas.artifacts import ExecutionReport
from oracle_hcm.services.orchestrator import OrchestrationResult, Orchestrator
from oracle_hcm.signing.keys import generate_keypair, save_keypair

pytestmark = [
    pytest.mark.docker,
    pytest.mark.skipif(not docker_is_ready(), reason="the docker daemon does not answer"),
]


@pytest.fixture
def orchestrator(tmp_path: Path) -> Iterator[Orchestrator]:
    keys = tmp_path / "keys"
    keys.mkdir()
    save_keypair(generate_keypair(), keys)
    config = AppConfig(
        sop_id="sop_lightweight",
        use_fake_backend=True,
        max_phase=5,
        keys_directory=keys,
        deployment_root=tmp_path / "deploy",
    )
    engine = build_orchestrator(config, data_root=tmp_path)
    try:
        yield engine
    finally:
        DeploymentService(
            config=DeploymentConfig(),
            root=tmp_path / "deploy",
            event_log=EventLog(tmp_path / "audit.jsonl"),
        ).shutdown()


async def _approve_all(orchestrator: Orchestrator) -> OrchestrationResult:
    """Run the task until every approval was granted."""
    result = await orchestrator.run("Add overtime pay")
    assert result.status == "awaiting_approval"
    assert result.approval is not None
    orchestrator._approvals.decide(
        result.approval.approval_id, approved=True, decided_by="jo"
    )

    result = await orchestrator.resume(result.run_id)
    assert result.status == "awaiting_approval"
    assert result.approval is not None
    orchestrator._approvals.decide(
        result.approval.approval_id, approved=True, decided_by="jo"
    )

    result = await orchestrator.resume(result.run_id)
    assert result.status == "awaiting_approval"
    assert result.approval is not None
    orchestrator._approvals.decide(
        result.approval.approval_id, approved=True, decided_by="jo"
    )

    return await orchestrator.resume(result.run_id)


async def test_a_task_is_signed_verified_and_deployed(orchestrator: Orchestrator) -> None:
    result = await _approve_all(orchestrator)

    assert result.status == "completed", result.failure
    outputs = result.sop_result.outputs if result.sop_result else {}
    assert "requirements" in outputs
    assert "code" in outputs
    assert "tests" in outputs
    assert "sandbox_run" in outputs
    assert "security_gate" in outputs
    assert "acceptance_gate" in outputs
    assert "sign" in outputs
    assert "deploy" in outputs

    sign = ExecutionReport.model_validate(outputs["sign"])
    assert sign.manifest_path
    assert await asyncio.to_thread(Path(sign.manifest_path).is_file)

    deploy = ExecutionReport.model_validate(outputs["deploy"])
    assert deploy.deployment is not None
    assert deploy.deployment.status == "deployed"
    assert deploy.deployment.steps
    assert deploy.deployment.steps[0].errors == 0


async def test_the_every_step_of_the_run_is_audited(
    orchestrator: Orchestrator, tmp_path: Path
) -> None:
    await _approve_all(orchestrator)

    events = [
        json.loads(line)
        for line in (tmp_path / "audit.jsonl").read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    actions = [event["action"] for event in events]

    assert "run_started" in actions
    assert "approval_requested" in actions
    assert "artifact_signed" in actions
    assert "deployment_verified" in actions
    assert "deployment_started" in actions
    assert "deployment_completed" in actions

    signed = next(event for event in events if event["action"] == "artifact_signed")
    assert signed["payload"]["root_hash"]
    assert signed["payload"]["manifest_signature"]
