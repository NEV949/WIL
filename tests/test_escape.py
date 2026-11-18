"""Escape pack: what a process that escaped the sandbox would try.

Every attempt runs in a real container of the sandbox image.
"""

from __future__ import annotations

import pytest

from security_attacks import (
    HOST_SECRET_MARKER,
    AttackOutcome,
    docker_is_ready,
    escape_attacks,
)

pytestmark = [
    pytest.mark.docker,
    pytest.mark.skipif(not docker_is_ready(), reason="the docker daemon does not answer"),
]


async def _outcome(attack: str) -> AttackOutcome:
    outcomes = await escape_attacks()
    return next(item for item in outcomes if item.attack == attack)


async def test_the_network_is_unreachable() -> None:
    outcome = await _outcome("network connect from inside the sandbox")

    assert outcome.result == "blocked"
    assert "NETWORK-ERROR" in outcome.output


async def test_a_write_outside_the_scratch_is_refused() -> None:
    outcome = await _outcome("write outside the scratch tmpfs")

    assert outcome.result == "blocked"
    assert "REFUSED /workspace/escape.txt" in outcome.output
    assert "REFUSED /etc/escape.txt" in outcome.output
    assert "WROTE /scratch/ok.txt" in outcome.output


async def test_a_file_of_the_host_cannot_be_read() -> None:
    outcome = await _outcome("read of a file of the host")

    assert outcome.result == "blocked"
    assert HOST_SECRET_MARKER not in outcome.output


async def test_the_memory_hog_is_stopped_by_the_limit() -> None:
    outcome = await _outcome("memory hog beyond the limit of the container")

    assert outcome.result == "blocked"
    assert outcome.exit_code != 0
    assert "the process was stopped by the memory limit" in outcome.detail


async def test_the_process_spawn_is_stopped_by_the_limit() -> None:
    outcome = await _outcome("process spawn beyond the limit of the container")

    assert outcome.result == "blocked"
    assert "FORK-ERROR" in outcome.output
    children = int(outcome.output.split("children")[-1].strip().split()[0])
    assert children < 64


async def test_the_infinite_loop_is_killed_by_the_timeout() -> None:
    outcome = await _outcome("infinite loop")

    assert outcome.result == "blocked"
    assert "124" in outcome.logged_event


async def test_the_sandbox_still_works_after_the_attacks() -> None:
    outcome = await _outcome("the sandbox after the escape attempts")

    assert outcome.result == "blocked"
