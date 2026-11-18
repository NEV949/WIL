"""The results tables of the deployment evaluation.

The tables in docs/deployment_evaluation.md are generated from the outcomes the
deployment scenarios observed. The test fails when the file and the
observations disagree, so a refusal that did not happen can never be hidden by
editing the document.
"""

from __future__ import annotations

import pytest

from deployment_report import build_report, report_path, scenarios
from deployment_scenarios import docker_is_ready

pytestmark = [
    pytest.mark.docker,
    pytest.mark.skipif(not docker_is_ready(), reason="the docker daemon does not answer"),
]


async def test_every_tamper_case_was_refused() -> None:
    tamper, _, _, _ = await scenarios()

    assert len(tamper) == 5
    for outcome in tamper:
        assert outcome.refused is True, f"'{outcome.case}' was not refused"
        assert outcome.reason, f"'{outcome.case}' was refused without a reason"
        assert outcome.logged_event == "deployment_refused"


async def test_the_report_holds_the_results_of_the_scenarios() -> None:
    tamper, rollout, rollback, downtime = await scenarios()

    expected = build_report(tamper, rollout, rollback, downtime)
    path = report_path()

    assert path.is_file(), f"the report is missing: {path}"
    assert path.read_text(encoding="utf-8") == expected, (
        "the report is out of date, regenerate it with 'python tests/deployment_report.py'"
    )
