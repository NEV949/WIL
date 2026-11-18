"""Security gates.

The pre-run gate refuses to let code reach the test run when the code breaks
the default-deny allowlist or uses a capability the requirement did not
declare. Its scanners run inside the sandbox image, with the code mounted
read-only and no network.

The post-run gate repeats the scan on the final code, audits the
dependencies of the host and turns the runtime events of the sandbox into
findings.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Final, Protocol

from oracle_hcm.schemas.artifacts import (
    ExecutionReport,
    RequirementSpec,
    RiskTier,
    SecurityFinding,
    Severity,
)
from oracle_hcm.security.ast_policy import AstPolicy, check_permissions, modules_of
from oracle_hcm.security.prompt_guard import GuardVerdict, PromptGuardClient, RegexPromptGuard
from oracle_hcm.security.risk import RiskClassifier
from oracle_hcm.security.scanners import ScannerSuite, host_pip_audit
from oracle_hcm.services.sandbox import (
    CommandResult,
    GateDecision,
    SandboxService,
    WorkspaceFile,
    materialise,
)

__all__ = [
    "PostRunSecurityGate",
    "PreRunChecker",
    "PreRunSecurityGate",
    "RequirementChecker",
    "SecurityGateAgent",
    "permission_findings",
    "runtime_findings",
]

_RUNTIME_SEVERITIES: Final[dict[str, Severity]] = {
    "network": "high",
    "process": "high",
    "file_write_outside_scratch": "high",
    "sensitive_file_read": "high",
    "dynamic_exec": "high",
    "native_code": "high",
    "file_write": "medium",
}


@dataclass(frozen=True)
class PreRunSecurityGate:
    """The scanners that run inside the sandbox before the suite."""

    scanners: ScannerSuite
    policy: AstPolicy = field(default_factory=AstPolicy)

    def commands(self) -> list[list[str]]:
        return self.scanners.commands()

    def files(self) -> list[WorkspaceFile]:
        return self.scanners.helper_files()

    def evaluate(self, results: list[CommandResult]) -> GateDecision:
        findings = list(self.scanners.parse(results))
        blocking = [finding for finding in findings if finding.blocking]
        return GateDecision(findings=tuple(findings), blocked=bool(blocking))


@dataclass(frozen=True)
class PostRunSecurityGate:
    """The checks that run after the suite."""

    scanners: ScannerSuite
    sandbox: SandboxService

    async def scan(self, directory: Path) -> list[SecurityFinding]:
        """Scan the final code inside the sandbox."""
        materialise(self.scanners.helper_files(), directory)
        results = await self.sandbox.run_in_directory(
            directory=directory,
            commands=self.scanners.commands(),
        )
        return self.scanners.parse(results)

    async def run(self, report: ExecutionReport) -> list[SecurityFinding]:
        """The final scan, the dependency audit and the runtime events."""
        findings: list[SecurityFinding] = []
        directory = report.workspace_path
        present = bool(directory) and await asyncio.to_thread(Path(directory).is_dir)
        if present:
            findings.extend(await self.scan(Path(directory)))
        else:
            findings.append(
                SecurityFinding(
                    rule="S000-scanner-error",
                    severity="medium",
                    message="the final scan could not run: the workspace is gone",
                    tool="scan",
                )
            )
        findings.extend(host_pip_audit())
        findings.extend(runtime_findings(report.security_events))
        return findings


def runtime_findings(events: list[str]) -> list[SecurityFinding]:
    """Turn the events the sandbox reported into findings."""
    findings: list[SecurityFinding] = []
    for event in events:
        category, _, detail = event.partition(":")
        severity = _RUNTIME_SEVERITIES.get(category, "medium")
        findings.append(
            SecurityFinding(
                rule=f"RUNTIME-{category}",
                severity=severity,
                message=f"the sandbox reported {category}: {detail[:200]}",
                tool="sandbox",
            )
        )
    return findings


def permission_findings(
    policy: AstPolicy,
    declared: list[str],
    sources: dict[str, str],
) -> list[SecurityFinding]:
    """Compare the declared permissions with the capabilities the code uses."""
    findings: list[SecurityFinding] = []
    local = modules_of(sources)
    for path, source in sources.items():
        result = policy.analyze(source, path, local)
        for finding in check_permissions(
            declared, result.capabilities, path, result.findings
        ):
            findings.append(
                SecurityFinding(
                    rule=finding.rule,
                    severity=finding.severity,
                    file=finding.file,
                    line=finding.line,
                    message=finding.message,
                    tool=finding.tool,
                )
            )
    return findings


class PreRunChecker(Protocol):
    """Checks that run on the host before the sandbox is started."""

    async def check(
        self, payload: dict[str, Any], files: list[WorkspaceFile]
    ) -> list[SecurityFinding]: ...


@dataclass
class RequirementChecker:
    """The requirement text and the declared permissions of the code."""

    policy: AstPolicy = field(default_factory=AstPolicy)
    guard: PromptGuardClient = field(default_factory=RegexPromptGuard)

    def _text(self, payload: dict[str, Any]) -> str:
        raw = payload.get("spec")
        if not raw:
            return str(payload.get("request", ""))
        spec = RequirementSpec.model_validate(raw)
        return " ".join(
            [
                spec.title,
                spec.description,
                *spec.acceptance_criteria,
                *spec.constraints,
                *spec.domain_entities,
            ]
        )

    async def check(
        self, payload: dict[str, Any], files: list[WorkspaceFile]
    ) -> list[SecurityFinding]:
        """Check the requirement text and the declared permissions."""
        findings: list[SecurityFinding] = []
        text = self._text(payload)
        verdict: GuardVerdict = await self.guard.inspect(text)
        for signal in verdict.signals:
            findings.append(
                SecurityFinding(
                    rule="S901-prompt-guard",
                    severity="high" if verdict.blocked else "medium",
                    message=f"the requirement text tripped the prompt guard: {signal}",
                    tool="prompt-guard",
                )
            )
        raw = payload.get("spec")
        declared = RequirementSpec.model_validate(raw).declared_permissions if raw else []
        sources = {item.path: item.content for item in files}
        findings.extend(permission_findings(self.policy, list(declared), sources))
        return findings


class SecurityGateAgent:
    """The SOP step that judges the run after the suite."""

    def __init__(
        self,
        sandbox: SandboxService,
        *,
        scanners: ScannerSuite | None = None,
        policy: AstPolicy | None = None,
        classifier: RiskClassifier | None = None,
        guard: PromptGuardClient | None = None,
        declared_tier: RiskTier = RiskTier.LOW,
    ) -> None:
        self._sandbox = sandbox
        self._scanners = scanners if scanners is not None else ScannerSuite()
        self._policy = policy if policy is not None else AstPolicy()
        self._classifier = classifier if classifier is not None else RiskClassifier(self._policy)
        self._guard = guard if guard is not None else RegexPromptGuard()
        self._declared_tier = declared_tier

    async def __call__(self, payload: dict[str, Any]) -> ExecutionReport:
        report = ExecutionReport.model_validate(payload.get("report", {}))
        raw = payload.get("spec")
        spec = RequirementSpec.model_validate(raw) if raw else None
        text = str(payload.get("text", ""))
        if spec is not None:
            text = " ".join(
                [spec.title, spec.description, *spec.acceptance_criteria, *spec.constraints]
            )
        findings = await PostRunSecurityGate(self._scanners, self._sandbox).run(report)
        verdict = await self._guard.inspect(text)
        for signal in verdict.signals:
            findings.append(
                SecurityFinding(
                    rule="S901-prompt-guard",
                    severity="high" if verdict.blocked else "medium",
                    message=f"the requirement text tripped the prompt guard: {signal}",
                    tool="prompt-guard",
                )
            )
        files = await self._workspace_files(report.workspace_path)
        assessment = self._classifier.classify(
            spec,
            [text],
            files=files,
            declared_tier=self._declared_tier,
        )
        return ExecutionReport(
            run_id=f"security-{report.run_id}",
            requirement_id=report.requirement_id,
            command="security_gate",
            exit_code=0,
            tests_passed=report.tests_passed,
            tests_failed=report.tests_failed,
            coverage_percent=report.coverage_percent,
            security_events=list(report.security_events),
            security_findings=findings,
            risk_tier=assessment.tier,
            risk_signals=list(assessment.signals),
            workspace_mount=report.workspace_mount,
            writable_paths=list(report.writable_paths),
            workspace_path=report.workspace_path,
        )

    async def _workspace_files(self, workspace_path: str) -> dict[str, str]:
        """The generated code of the run, for the AST re-check of the risk."""
        if not workspace_path:
            return {}
        root = Path(workspace_path)
        sources: dict[str, str] = {}
        for path in sorted(await asyncio.to_thread(lambda: list(root.rglob("*.py")))):
            if "tests" in path.parts:
                continue
            try:
                sources[str(path.relative_to(root))] = await asyncio.to_thread(
                    path.read_text, encoding="utf-8", errors="replace"
                )
            except OSError:
                continue
        return sources
