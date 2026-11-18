"""The results table of the security evaluation.

The table in docs/security_evaluation.md is generated from the outcomes the
packs observed. The test fails when the file and the observations disagree, so
an attack that was not blocked can never be hidden by editing the document.
"""

from __future__ import annotations

import pytest

from acceptance_tasks import outcomes
from security_attacks import docker_is_ready, escape_attacks, redteam_attacks, sample_scans
from security_report import build_report, report_path

pytestmark = [
    pytest.mark.docker,
    pytest.mark.skipif(not docker_is_ready(), reason="the docker daemon does not answer"),
]


async def test_every_attack_was_blocked_or_detected() -> None:
    redteam = await redteam_attacks()
    escape = await escape_attacks()

    for outcome in [*redteam, *escape]:
        assert outcome.result in ("blocked", "detected"), (
            f"the attack '{outcome.attack}' was {outcome.result}: {outcome.detail}"
        )


async def test_the_report_holds_the_results_of_the_packs() -> None:
    redteam = await redteam_attacks()
    escape = await escape_attacks()
    acceptance = await outcomes()
    scans = await sample_scans()

    expected = build_report(
        redteam, escape, acceptance["passing"], acceptance["blocked"], scans
    )
    path = report_path()

    assert path.is_file(), f"the report is missing: {path}"
    assert path.read_text(encoding="utf-8") == expected, (
        "the report is out of date, regenerate it with 'python tests/security_report.py'"
    )
