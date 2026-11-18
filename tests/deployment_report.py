"""The deployment evaluation report.

The report is built from the outcomes of the deployment scenarios, so that the
tables in docs/deployment_evaluation.md can never drift away from what the
engine actually did.
"""

from __future__ import annotations

import asyncio
import tempfile
import textwrap
from pathlib import Path

from deployment_scenarios import (
    DowntimeOutcome,
    Harness,
    RollbackOutcome,
    RolloutOutcome,
    TamperOutcome,
    downtime_scenario,
    rollback_scenario,
    rollout_scenario,
    tamper_scenarios,
)

__all__ = ["build_report", "report_path", "scenarios", "write_report"]

REPOSITORY = Path(__file__).resolve().parents[1]


def report_path() -> Path:
    """Where the report is written."""
    return REPOSITORY / "docs" / "deployment_evaluation.md"


def _table(rows: list[list[str]]) -> list[str]:
    lines = ["| " + " | ".join(rows[0]) + " |"]
    lines.append("|" + "|".join([" --- "] * len(rows[0])) + "|")
    for row in rows[1:]:
        lines.append("| " + " | ".join(row) + " |")
    return lines


def _tamper_table(outcomes: list[TamperOutcome]) -> list[str]:
    rows: list[list[str]] = [["Tamper", "Refused", "Reason", "Logged event"]]
    for outcome in outcomes:
        rows.append(
            [
                outcome.case,
                "yes" if outcome.refused else "no",
                outcome.reason,
                outcome.logged_event or "-",
            ]
        )
    return _table(rows)


def _rollout_table(outcome: RolloutOutcome) -> list[str]:
    rows: list[list[str]] = [["Traffic", "Requests", "Errors", "Error rate"]]
    for percent, requests, errors, rate in outcome.steps:
        rows.append([f"{percent}%", str(requests), str(errors), f"{rate:.4f}"])
    return _table(rows)


def _paragraph(text: str) -> list[str]:
    """A paragraph, wrapped by its words and not by the source of the code."""
    return textwrap.wrap(text, width=72) or [""]


def build_report(
    tamper: list[TamperOutcome],
    rollout: RolloutOutcome,
    rollback: RollbackOutcome,
    downtime: DowntimeOutcome,
) -> str:
    """The markdown of the report."""
    retired = "was retired" if rollout.retired_version else "still carries the traffic"
    restored = (
        "the one that was running before the rollout"
        if rollback.restored_version
        else "not restored"
    )
    failed = (
        "None of them failed."
        if downtime.failures == 0
        else f"{downtime.failures} of them failed."
    )
    lines = [
        "# Deployment evaluation",
        "",
    ]
    lines.extend(
        _paragraph(
            "Every result below was observed against the docker daemon: the image of the "
            "artifact was built, the container was started beside the running version "
            "and the traffic was shifted through nginx. The tables are generated from "
            "the outcomes the scenarios observed, so they cannot drift away from them."
        )
    )
    lines.extend(
        [
            "",
            "## Tamper: a signed artifact that was changed",
            "",
        ]
    )
    lines.extend(
        _paragraph(
            "Each case below changed the artifact or its signature after the signing. "
            "The engine recomputed every file hash, the root hash, the signature and "
            "the link to the audit log, and refused the deployment."
        )
    )
    lines.append("")
    lines.extend(_tamper_table(tamper))
    lines.extend(
        [
            "",
            "## Rollout: the traffic shifts in steps",
            "",
        ]
    )
    lines.extend(
        _paragraph(
            f"The rollout ended with the status '{rollout.status}'. The version that "
            f"carried the traffic before the rollout {retired}."
        )
    )
    lines.append("")
    lines.extend(_rollout_table(rollout))
    lines.extend(
        [
            "",
            "## Rollback: the new version fails",
            "",
        ]
    )
    lines.extend(
        _paragraph(
            f"The status of the deployment was '{rollback.status}'. The event "
            f"'{rollback.logged_event}' was written to the audit log with the reason "
            f"'{rollback.reason}'. The version that carried the traffic again was "
            f"{restored}."
        )
    )
    lines.extend(
        [
            "",
            "## Zero downtime: the requests during the rollout",
            "",
        ]
    )
    lines.extend(
        _paragraph(
            "A steady stream of requests ran against the router while the traffic was "
            f"shifted. {failed}"
        )
    )
    lines.append("")
    lines.extend(_rollout_table(_as_rollout(downtime)))
    lines.append("")
    return "\n".join(lines)


def _as_rollout(downtime: DowntimeOutcome) -> RolloutOutcome:
    """The steps of the rollout that carried the stream."""
    return RolloutOutcome(
        status=downtime.status,
        steps=downtime.steps,
        retired_version="",
        version="",
    )


async def scenarios() -> tuple[
    list[TamperOutcome], RolloutOutcome, RollbackOutcome, DowntimeOutcome
]:
    """Run every scenario and collect the outcomes."""
    tamper = await tamper_scenarios()
    with tempfile.TemporaryDirectory(prefix="oracle-deploy-report-") as directory:
        root = Path(directory)
        harness = Harness(root, f"oracle-deploy-report-{root.name}")
        try:
            rollout = await rollout_scenario(harness)
            rollback = await rollback_scenario(harness)
            downtime = await downtime_scenario(harness)
        finally:
            harness.shutdown()
    return tamper, rollout, rollback, downtime


def write_report() -> Path:
    """Run the scenarios and write the report."""
    tamper, rollout, rollback, downtime = asyncio.run(scenarios())
    path = report_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(build_report(tamper, rollout, rollback, downtime), encoding="utf-8")
    return path


if __name__ == "__main__":
    print(write_report())
