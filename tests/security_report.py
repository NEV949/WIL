"""The security evaluation report.

The report is built from the outcomes of the packs, so that the table in
docs/security_evaluation.md can never drift away from what the tests observed.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

from acceptance_tasks import Outcome, outcomes
from security_attacks import (
    AttackOutcome,
    SampleScan,
    escape_attacks,
    redteam_attacks,
    sample_scans,
)

__all__ = ["build_report", "report_path", "write_report"]

REPOSITORY = Path(__file__).resolve().parents[1]


def report_path() -> Path:
    """Where the report is written."""
    return REPOSITORY / "docs" / "security_evaluation.md"


def _table(rows: list[list[str]]) -> list[str]:
    lines = ["| " + " | ".join(rows[0]) + " |"]
    lines.append("|" + "|".join([" --- "] * len(rows[0])) + "|")
    for row in rows[1:]:
        lines.append("| " + " | ".join(row) + " |")
    return lines


def _attack_table(outcomes: list[AttackOutcome]) -> list[str]:
    rows: list[list[str]] = [["Attack", "Stage that blocked it", "Result", "Logged event"]]
    for outcome in outcomes:
        rows.append(
            [
                outcome.attack,
                outcome.stage,
                outcome.result,
                outcome.logged_event,
            ]
        )
    return _table(rows)


def _acceptance_table(passing: Outcome, blocked: Outcome) -> list[str]:
    names = list(passing.verdicts())
    rows: list[list[str]] = [["Acceptance condition", "Passing task", "Blocked task"]]
    for name in names:
        rows.append(
            [
                name,
                "pass" if passing.verdicts()[name] else "fail",
                "pass" if blocked.verdicts()[name] else "fail",
            ]
        )
    return _table(rows)


def _findings_json(scan: SampleScan) -> list[str]:
    payload = [item.model_dump(mode="json") for item in scan.findings]
    text = json.dumps(payload, indent=2, ensure_ascii=False)
    return ["```json", *text.splitlines(), "```"]


def build_report(
    redteam: list[AttackOutcome],
    escape: list[AttackOutcome],
    passing: Outcome,
    blocked: Outcome,
    scans: dict[str, SampleScan],
) -> str:
    """The markdown of the report."""
    lines = [
        "# Security evaluation",
        "",
        "Every attack below was run against the engine as it is: the scanners ran",
        "inside the sandbox image with the code mounted read-only and no network,",
        "and the escape attempts ran in a real container. The table is generated",
        "from the outcomes the packs observed, so it cannot drift away from them.",
        "",
        "## Red team: attacks carried by the generated code",
        "",
    ]
    lines.extend(_attack_table(redteam))
    lines.extend(
        [
            "",
            "## Escape attempts: attacks carried out from inside the container",
            "",
        ]
    )
    lines.extend(_attack_table(escape))
    lines.extend(
        [
            "",
            "## The scanners on a clean sample and on a vulnerable sample",
            "",
            "Bandit, Ruff, Semgrep with the local rules and detect-secrets ran in",
            "the sandbox image against both samples. The findings are the ones the",
            "engine acts on.",
            "",
            "### Clean sample",
            "",
        ]
    )
    lines.extend(_findings_json(scans["clean"]))
    lines.extend(
        [
            "",
            "### Vulnerable sample",
            "",
        ]
    )
    lines.extend(_findings_json(scans["vulnerable"]))
    lines.extend(
        [
            "",
            "## Acceptance gate",
            "",
            "The two tasks below ran through the sandbox, the security gate and the",
            "acceptance gate. Every condition is reported separately.",
            "",
        ]
    )
    lines.extend(_acceptance_table(passing, blocked))
    lines.append("")
    return "\n".join(lines)


def write_report() -> Path:
    """Run the packs and write the report."""
    redteam = asyncio.run(redteam_attacks())
    escape = asyncio.run(escape_attacks())
    acceptance = asyncio.run(outcomes())
    scans = asyncio.run(sample_scans())
    path = report_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        build_report(
            redteam,
            escape,
            acceptance["passing"],
            acceptance["blocked"],
            scans,
        ),
        encoding="utf-8",
    )
    return path


if __name__ == "__main__":
    print(write_report())
