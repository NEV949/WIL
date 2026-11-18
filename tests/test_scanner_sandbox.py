"""The scanner suite, for real, inside the sandbox image.

The scanners run with the same hardening as a test run: no network, no
capabilities and the code mounted read-only.
"""

from __future__ import annotations

import json

import pytest

from security_attacks import docker_is_ready, sample_scans

pytestmark = [
    pytest.mark.docker,
    pytest.mark.skipif(not docker_is_ready(), reason="the docker daemon does not answer"),
]


async def test_the_clean_sample_passes_every_scanner() -> None:
    scan = (await sample_scans())["clean"]

    blocking = [finding for finding in scan.findings if finding.blocking]
    assert blocking == [], [finding.rule for finding in blocking]
    assert {finding.rule for finding in scan.findings} <= {"B101", "S101"}
    assert json.dumps([finding.model_dump() for finding in scan.findings])


async def test_the_vulnerable_sample_is_blocked_by_the_scanners() -> None:
    scan = (await sample_scans())["vulnerable"]

    rules = {finding.rule for finding in scan.blocking}
    assert "S605" in rules
    assert "S310" in rules
    assert "S306-obfuscated-exec" in rules
    assert "S403-import-not-allowed" in rules
    assert "B605" in rules
    assert "SECRET-AWS-Access-Key" in rules
    assert json.dumps([finding.model_dump() for finding in scan.findings])


async def test_every_scanner_reports_json() -> None:
    scan = (await sample_scans())["vulnerable"]

    tools = {finding.tool for finding in scan.findings}
    assert tools == {"ast", "bandit", "ruff", "semgrep", "detect-secrets"}
    for finding in scan.findings:
        payload = finding.model_dump()
        assert set(payload) == {"rule", "severity", "file", "line", "message", "tool"}
        assert payload["severity"] in ("low", "medium", "high", "critical")
