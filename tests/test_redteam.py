"""Red team pack: the attacks a generated code or a requirement may carry.

The scanners run for real inside the sandbox image, with the same hardening
as a test run: no network, no capabilities and the code mounted read-only.
"""

from __future__ import annotations

import pytest

from security_attacks import RED_TEAM_SAMPLES, docker_is_ready, redteam_attacks

pytestmark = [
    pytest.mark.docker,
    pytest.mark.skipif(not docker_is_ready(), reason="the docker daemon does not answer"),
]


async def test_every_red_team_attack_is_stopped() -> None:
    outcomes = await redteam_attacks()

    by_attack = {outcome.attack: outcome for outcome in outcomes}
    for sample in RED_TEAM_SAMPLES:
        outcome = by_attack[sample.attack]
        assert outcome.result in ("blocked", "detected"), (
            f"the attack '{sample.attack}' was not stopped: {outcome.detail}"
        )


async def test_the_prompt_injection_in_the_requirement_is_refused() -> None:
    outcomes = await redteam_attacks()

    outcome = next(
        item for item in outcomes if "prompt injection" in item.attack
    )

    assert outcome.result == "blocked"
    assert outcome.logged_event == "S901-prompt-guard"


@pytest.mark.parametrize(
    ("attack", "expected"),
    [
        ("os.system()", "S605"),
        ("outbound HTTP", "S310"),
        ("base64 obfuscated exec", "S306-obfuscated-exec"),
        ("fork bomb", "S404-fork"),
        ("hard coded secret", "S105"),
        ("import of a package", "S403-import-not-allowed"),
    ],
)
async def test_the_generated_code_is_rejected_before_it_runs(
    attack: str, expected: str
) -> None:
    outcomes = await redteam_attacks()

    outcome = next(item for item in outcomes if attack in item.attack)

    assert outcome.result == "blocked"
    assert expected in outcome.logged_event


async def test_the_runtime_attacks_are_reported_by_the_sandbox() -> None:
    outcomes = await redteam_attacks()

    read = next(item for item in outcomes if "/etc/passwd" in item.attack)
    fork = next(item for item in outcomes if item.attack.startswith("fork in"))

    assert read.result == "detected"
    assert "RUNTIME-sensitive_file_read" in read.logged_event
    assert fork.result == "detected"
    assert "RUNTIME-process" in fork.logged_event
