"""Static scanners.

Bandit, Ruff, Semgrep and detect-secrets run inside the sandbox image, with
the same hardening as the test run: no network, no capabilities and the code
mounted read-only. The AST allowlist runs there too, next to the code it
inspects. Every scanner reports its findings as JSON, and the engine turns
them into ``SecurityFinding`` objects.

pip-audit runs on the host because it needs the dependency set of the
environment that runs the engine.
"""

from __future__ import annotations

import json
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final

from oracle_hcm.paths import semgrep_rules_path
from oracle_hcm.schemas.artifacts import SecurityFinding, Severity
from oracle_hcm.security.ast_runner import MARKER as AST_MARKER
from oracle_hcm.services.sandbox import CommandResult, WorkspaceFile

__all__ = [
    "HOST_PIP_AUDIT_TIMEOUT",
    "SCANNER_TIMEOUT_SECONDS",
    "ScannerSuite",
    "host_pip_audit",
]

SCANNER_TIMEOUT_SECONDS: Final[int] = 300
HOST_PIP_AUDIT_TIMEOUT: Final[int] = 300

SANDBOX: Final[str] = "/workspace"
HELPERS: Final[str] = "_scanners"

_RUFF_HIGH: Final[frozenset[str]] = frozenset(
    {
        "S102",
        "S105",
        "S106",
        "S107",
        "S307",
        "S310",
        "S403",
        "S404",
        "S501",
        "S502",
        "S503",
        "S504",
        "S505",
        "S506",
        "S507",
        "S508",
        "S601",
        "S602",
        "S603",
        "S604",
        "S605",
        "S606",
        "S607",
        "S608",
        "S609",
        "S610",
        "S611",
        "S612",
    }
)
_RUFF_LOW: Final[frozenset[str]] = frozenset(
    {"S101", "S104", "S108", "S110", "S112", "S113", "S311", "S321"}
)


def _severity_rank(value: str) -> Severity:
    """Map a scanner severity onto the four levels the engine uses."""
    lowered = value.strip().lower()
    if lowered == "critical":
        return "critical"
    if lowered in ("error", "high", "fail", "blocker"):
        return "high"
    if lowered in ("medium", "warning", "warn"):
        return "medium"
    return "low"


def _severity(value: str) -> Severity:
    """Keep a severity the engine knows and fall back to the middle one."""
    lowered = value.strip().lower()
    if lowered == "low":
        return "low"
    if lowered == "medium":
        return "medium"
    if lowered == "high":
        return "high"
    if lowered == "critical":
        return "critical"
    return "medium"


def _relative(path: str) -> str:
    """Strip the sandbox root from a path so the finding is portable."""
    for prefix in (f"{SANDBOX}/", SANDBOX):
        if path.startswith(prefix):
            return path[len(prefix) :].lstrip("/")
    return path


def _json_or_none(text: str) -> Any:
    """Parse JSON, tolerating leading noise on stdout."""
    try:
        return json.loads(text.strip())
    except ValueError:
        pass
    for opener in ("{", "["):
        start = text.find(opener)
        if start < 0:
            continue
        try:
            return json.loads(text[start:])
        except ValueError:
            continue
    return None


def _semgrep_rule(check_id: str) -> str:
    """The rule id without the path of the local rules file."""
    prefix = f"{HELPERS}."
    if check_id.startswith(prefix):
        return check_id[len(prefix) :]
    return check_id


@dataclass(frozen=True)
class ScannerSuite:
    """The scanners and the files they need inside the sandbox."""

    python: str = "/opt/venv/bin/python"
    workspace: str = SANDBOX

    def commands(self) -> list[list[str]]:
        """The scanner commands, in the order they must run."""
        helpers = f"{self.workspace}/{HELPERS}"
        return [
            [self.python, f"{helpers}/ast_runner.py", self.workspace],
            [
                "/opt/venv/bin/bandit",
                "-r",
                self.workspace,
                "-f",
                "json",
                "-q",
                "-x",
                f"*/{HELPERS}/*",
            ],
            [
                "/opt/venv/bin/ruff",
                "check",
                "--no-cache",
                "--select",
                "S",
                "--output-format",
                "json",
                "--exclude",
                HELPERS,
                self.workspace,
            ],
            [
                "/opt/venv/bin/semgrep",
                "--config",
                f"{helpers}/oracle_rules.yml",
                "--json",
                "--quiet",
                "--error",
                "--disable-version-check",
                "--metrics",
                "off",
                "--exclude",
                HELPERS,
                self.workspace,
            ],
            [
                "/opt/venv/bin/detect-secrets",
                "scan",
                "--all-files",
                "--exclude-files",
                f".*/{HELPERS}/.*",
                self.workspace,
            ],
        ]

    def helper_files(self) -> list[WorkspaceFile]:
        """The files that are copied into the sandbox for the scanners."""
        package = Path(__file__).resolve().parent
        return [
            WorkspaceFile(
                path=f"{HELPERS}/ast_policy.py",
                content=(package / "ast_policy.py").read_text(encoding="utf-8"),
            ),
            WorkspaceFile(
                path=f"{HELPERS}/ast_runner.py",
                content=(package / "ast_runner.py").read_text(encoding="utf-8"),
            ),
            WorkspaceFile(
                path=f"{HELPERS}/import_policy.json",
                content=(
                    package.parents[2] / "config" / "security" / "import_policy.json"
                ).read_text(encoding="utf-8"),
            ),
            WorkspaceFile(
                path=f"{HELPERS}/oracle_rules.yml",
                content=semgrep_rules_path().read_text(encoding="utf-8"),
            ),
        ]

    def tool_of(self, command: list[str]) -> str:
        """The name of the scanner a command belongs to."""
        joined = " ".join(command)
        if "ast_runner.py" in joined:
            return "ast"
        if "bandit" in joined:
            return "bandit"
        if "ruff" in joined:
            return "ruff"
        if "semgrep" in joined:
            return "semgrep"
        if "detect-secrets" in joined:
            return "detect-secrets"
        return "unknown"

    def parse(self, results: list[CommandResult]) -> list[SecurityFinding]:
        """Turn the scanner output into findings."""
        findings: list[SecurityFinding] = []
        for result in results:
            tool = self.tool_of(result.command.split())
            if tool == "ast":
                findings.extend(self._parse_ast(result.stdout))
            elif tool == "bandit":
                findings.extend(self._parse_bandit(result))
            elif tool == "ruff":
                findings.extend(self._parse_ruff(result))
            elif tool == "semgrep":
                findings.extend(self._parse_semgrep(result))
            elif tool == "detect-secrets":
                findings.extend(self._parse_detect_secrets(result))
        return findings

    def _parse_ast(self, stdout: str) -> list[SecurityFinding]:
        if AST_MARKER not in stdout:
            return [
                SecurityFinding(
                    rule="S000-scanner-error",
                    severity="high",
                    message="the AST scanner produced no report",
                    tool="ast",
                )
            ]
        payload = _json_or_none(stdout.split(AST_MARKER, 1)[1])
        if not isinstance(payload, list):
            return [
                SecurityFinding(
                    rule="S000-scanner-error",
                    severity="high",
                    message="the AST scanner report could not be read",
                    tool="ast",
                )
            ]
        findings: list[SecurityFinding] = []
        for item in payload:
            if not isinstance(item, dict):
                continue
            findings.append(
                SecurityFinding(
                    rule=str(item.get("rule", "S000")),
                    severity=_severity(str(item.get("severity", "medium"))),
                    file=str(item.get("file", "")),
                    line=int(item.get("line", 0) or 0),
                    message=str(item.get("message", "")),
                    tool="ast",
                )
            )
        return findings

    def _parse_bandit(self, result: CommandResult) -> list[SecurityFinding]:
        payload = _json_or_none(result.stdout)
        if not isinstance(payload, dict):
            return [self._scanner_error("bandit", result)]
        findings: list[SecurityFinding] = []
        for item in payload.get("results", []):
            if not isinstance(item, dict):
                continue
            findings.append(
                SecurityFinding(
                    rule=str(item.get("test_id", "B000")),
                    severity=_severity_rank(str(item.get("issue_severity", "MEDIUM"))),
                    file=_relative(str(item.get("filename", ""))),
                    line=int(item.get("line_number", 0) or 0),
                    message=str(item.get("issue_text", "")),
                    tool="bandit",
                )
            )
        return findings

    def _parse_ruff(self, result: CommandResult) -> list[SecurityFinding]:
        payload = _json_or_none(result.stdout)
        if not isinstance(payload, list):
            return [self._scanner_error("ruff", result)]
        findings: list[SecurityFinding] = []
        for item in payload:
            if not isinstance(item, dict):
                continue
            code = str(item.get("code", "S000"))
            severity: Severity
            if code in _RUFF_HIGH:
                severity = "high"
            elif code in _RUFF_LOW:
                severity = "low"
            else:
                severity = "medium"
            location = item.get("location")
            line = int(location.get("row", 0) or 0) if isinstance(location, dict) else 0
            findings.append(
                SecurityFinding(
                    rule=code,
                    severity=severity,
                    file=_relative(str(item.get("filename", ""))),
                    line=line,
                    message=str(item.get("message", "")),
                    tool="ruff",
                )
            )
        return findings

    def _parse_semgrep(self, result: CommandResult) -> list[SecurityFinding]:
        payload = _json_or_none(result.stdout)
        if not isinstance(payload, dict):
            return [self._scanner_error("semgrep", result)]
        findings: list[SecurityFinding] = []
        for item in payload.get("results", []):
            if not isinstance(item, dict):
                continue
            raw_extra = item.get("extra")
            extra: dict[str, Any] = raw_extra if isinstance(raw_extra, dict) else {}
            raw_start = item.get("start")
            start: dict[str, Any] = raw_start if isinstance(raw_start, dict) else {}
            findings.append(
                SecurityFinding(
                    rule=_semgrep_rule(str(item.get("check_id", "S000"))),
                    severity=_severity_rank(str(extra.get("severity", "WARNING"))),
                    file=_relative(str(item.get("path", ""))),
                    line=int(start.get("line", 0) or 0),
                    message=str(extra.get("message", "")),
                    tool="semgrep",
                )
            )
        return findings

    def _parse_detect_secrets(self, result: CommandResult) -> list[SecurityFinding]:
        payload = _json_or_none(result.stdout)
        if not isinstance(payload, dict):
            return [self._scanner_error("detect-secrets", result)]
        findings: list[SecurityFinding] = []
        results = payload.get("results")
        if not isinstance(results, dict):
            return findings
        for filename, entries in results.items():
            if not isinstance(entries, list):
                continue
            for entry in entries:
                if not isinstance(entry, dict):
                    continue
                kind = str(entry.get("type", "Secret"))
                findings.append(
                    SecurityFinding(
                        rule=f"SECRET-{kind.replace(' ', '-')}",
                        severity="high",
                        file=_relative(str(filename)),
                        line=int(entry.get("line_number", 0) or 0),
                        message=f"a secret of type '{kind}' is present in the generated code",
                        tool="detect-secrets",
                    )
                )
        return findings

    def _scanner_error(self, tool: str, result: CommandResult) -> SecurityFinding:
        detail = (result.stderr or result.stdout or "").strip().splitlines()
        message = detail[-1] if detail else f"{tool} exited with {result.exit_code}"
        return SecurityFinding(
            rule="S000-scanner-error",
            severity="high",
            message=f"the {tool} scanner did not run: {message[:300]}",
            tool=tool,
        )


def host_pip_audit(timeout: int = HOST_PIP_AUDIT_TIMEOUT) -> list[SecurityFinding]:
    """Audit the dependencies of the host environment."""
    try:
        completed = subprocess.run(
            [sys.executable, "-m", "pip_audit", "--format", "json"],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return [
            SecurityFinding(
                rule="S000-pip-audit",
                severity="medium",
                message=f"the dependency audit could not be completed: {exc}",
                tool="pip-audit",
            )
        ]
    if completed.returncode not in (0, 1):
        detail = (completed.stderr or completed.stdout or "").strip().splitlines()
        return [
            SecurityFinding(
                rule="S000-pip-audit",
                severity="medium",
                message=(
                    "the dependency audit could not be completed: "
                    f"{detail[-1] if detail else completed.returncode}"
                ),
                tool="pip-audit",
            )
        ]
    payload = _json_or_none(completed.stdout)
    if not isinstance(payload, dict):
        return [
            SecurityFinding(
                rule="S000-pip-audit",
                severity="medium",
                message="the dependency audit report could not be read",
                tool="pip-audit",
            )
        ]
    findings: list[SecurityFinding] = []
    for dependency in payload.get("dependencies", []):
        if not isinstance(dependency, dict):
            continue
        for vulnerability in dependency.get("vulns", []):
            if not isinstance(vulnerability, dict):
                continue
            identifier = str(vulnerability.get("id", "PYSEC-0000"))
            fixes = vulnerability.get("fix_versions") or []
            findings.append(
                SecurityFinding(
                    rule=identifier,
                    severity="high",
                    file=str(dependency.get("name", "")),
                    message=(
                        f"{dependency.get('name', '')} {dependency.get('version', '')} is affected "
                        f"by {identifier}"
                        + (f" (fixed in {', '.join(str(item) for item in fixes)})" if fixes else "")
                    ),
                    tool="pip-audit",
                )
            )
    return findings
