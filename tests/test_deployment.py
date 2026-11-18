"""Deployment of a signed artifact: rollout, rollback and zero downtime.

These tests need the docker daemon. They build the image of the artifact,
start it beside the running version and shift the traffic through nginx.
"""

from __future__ import annotations

import asyncio
from collections.abc import Iterator
from pathlib import Path

import pytest
import requests

from deployment_scenarios import (
    BROKEN_PROBE,
    GOOD,
    Harness,
    downtime_scenario,
    rollback_scenario,
    rollout_scenario,
)

pytestmark = pytest.mark.docker


@pytest.fixture
def harness(tmp_path: Path) -> Iterator[Harness]:
    deployment = Harness(tmp_path, f"oracle-deploy-test-{tmp_path.name}")
    try:
        yield deployment
    finally:
        deployment.shutdown()


async def test_the_first_version_carries_the_traffic(harness: Harness) -> None:
    workspace = harness.workspace(GOOD, "v1")

    outcome = await harness.deploy(workspace, artifact_id="v1")

    assert outcome.status == "deployed"
    assert outcome.steps[0].percent == 100
    assert outcome.steps[0].errors == 0
    assert outcome.steps[0].requests == 100


async def test_the_rollout_shifts_the_traffic_in_steps(harness: Harness) -> None:
    outcome = await rollout_scenario(harness)

    assert outcome.status == "deployed"
    assert [step[0] for step in outcome.steps] == [10, 50, 100]
    assert all(step[2] == 0 for step in outcome.steps)
    assert outcome.retired_version


async def test_a_broken_version_is_rolled_back(harness: Harness) -> None:
    outcome = await rollback_scenario(harness)

    assert outcome.status == "rolled_back"
    assert "error rate" in outcome.reason
    assert outcome.logged_event == "deployment_rolled_back"
    assert outcome.restored_version


async def test_the_old_version_serves_after_the_rollback(harness: Harness) -> None:
    first = harness.workspace(GOOD, "v1")
    second = harness.workspace(
        {**GOOD, "pkg/broken.py": b"def boom() -> str:\n    raise ValueError\n"}, "v2"
    )

    await harness.deploy(first, artifact_id="v1")
    await harness.deploy(second, artifact_id="v2", probe=BROKEN_PROBE)

    base = f"http://127.0.0.1:{harness.service.config.router_port}"
    response = await asyncio.to_thread(requests.get, f"{base}/health", timeout=10)

    assert response.status_code == 200
    assert response.json()["status"] == "ok"


async def test_the_rollout_drops_no_request(harness: Harness) -> None:
    outcome = await downtime_scenario(harness)

    assert outcome.status == "deployed"
    assert outcome.requests >= 100, "the stream did not run during the rollout"
    assert outcome.failures == 0


async def test_the_broken_version_is_detected_by_the_probe(harness: Harness) -> None:
    """The probe of the broken version fails, so the rollout can see it."""
    workspace = harness.workspace(
        {**GOOD, "pkg/broken.py": b"def boom() -> str:\n    raise ValueError\n"}, "v2"
    )

    outcome = await harness.deploy(workspace, artifact_id="v2", probe=BROKEN_PROBE)

    assert outcome.status == "rolled_back"
    assert outcome.steps
    assert outcome.steps[0].errors > 0


async def test_the_deployment_is_hardened(harness: Harness) -> None:
    workspace = harness.workspace(GOOD, "v1")
    await harness.deploy(workspace, artifact_id="v1")

    compose = (harness.service.compose_dir / "docker-compose.yml").read_text(encoding="utf-8")
    networks = compose.split("networks:", 1)[1]

    assert "oracle-net" not in networks
    assert f"name: {harness.service.config.network_name}" in networks
    assert "read_only: true" in compose
    assert "cap_drop:" in compose
    assert "no-new-privileges:true" in compose
    assert 'user: "10001:10001"' in compose
    assert '"127.0.0.1:' in compose
