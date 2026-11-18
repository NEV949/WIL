"""Iterative security feedback and repair through the existing agents."""

from __future__ import annotations

import json
import re
import time
from collections.abc import Awaitable, Callable
from typing import Any

from pydantic import BaseModel

from oracle_hcm.log.conversation import ConversationStore
from oracle_hcm.redaction import redact, redact_text
from oracle_hcm.schemas.artifacts import (
    CodePatch,
    DebugPatch,
    ExecutionReport,
    FileChange,
    SecurityFinding,
    TestSuite,
)
from oracle_hcm.security.ast_policy import BLOCKED_IMPORTS
from oracle_hcm.services.sandbox import _test_path

__all__ = ["SecurityRepairAgent"]

Agent = Callable[[dict[str, Any]], Awaitable[BaseModel]]


class SecurityRepairAgent:
    """Rescan, repair, and rerun until clean or the configured limit is reached."""

    def __init__(
        self,
        *,
        coder: Agent,
        debugger: Agent,
        sandbox_runner: Agent,
        security_gate: Agent,
        conversations: ConversationStore,
        max_attempts: int = 3,
    ) -> None:
        self._coder = coder
        self._debugger = debugger
        self._sandbox_runner = sandbox_runner
        self._security_gate = security_gate
        self._conversations = conversations
        self._max_attempts = max(1, max_attempts)

    async def __call__(self, payload: dict[str, Any]) -> ExecutionReport:
        code = CodePatch.model_validate(payload.get("code", {}))
        tests = TestSuite.model_validate(payload.get("tests", {}))
        report = ExecutionReport.model_validate(payload.get("report", {}))
        spec = payload.get("spec", {})
        run_id = str(payload.get("run_id", ""))
        tenant_id = str(payload.get("tenant_id", "default"))
        history: list[dict[str, Any]] = []

        security = await self._scan(report, spec)
        if not self._blocking(security):
            return security

        for attempt in range(1, self._max_attempts + 1):
            started = time.monotonic()
            records_before = {item.call_id for item in self._conversations.read_all()}
            findings_before = [
                finding.model_dump(mode="json") for finding in security.security_findings
            ]
            context = self._repair_context(
                code=code,
                tests=tests,
                findings=security.security_findings,
                attempt=attempt,
                history=history,
            )
            agents_used = ["coder"]
            modified_files: list[str] = []
            errors: list[str] = []
            fallback_reason = ""
            outcome = "repair_failed"
            coder_failed = False
            requirement_conflict = False

            try:
                repaired = await self._coder(
                    {
                        "spec": self._redact(spec),
                        "current_code": context["source_files"],
                        "tests": context["tests"],
                        "security_repair": context,
                        "run_id": run_id,
                        "tenant_id": tenant_id,
                    }
                )
                if not isinstance(repaired, CodePatch):
                    raise TypeError("the Coder did not return a CodePatch")
                modified_files.extend(self._modified_files(code, repaired))
                code = repaired
            except Exception as exc:
                coder_failed = True
                fallback_reason = "Coder could not produce a valid repair"
                errors.append(redact_text(f"Coder {type(exc).__name__}: {exc}"))

            if not coder_failed:
                try:
                    report = await self._run_sandbox(
                        report=report,
                        code=code,
                        tests=tests,
                        spec=spec,
                        run_id=run_id,
                        tenant_id=tenant_id,
                    )
                    security = await self._scan(report, spec)
                    if report.exit_code != 0 or report.tests_failed > 0:
                        fallback_reason = "Coder repair introduced execution or test failures"
                    elif self._blocking(security):
                        fallback_reason = "blocking security findings remain after Coder repair"
                        requirement_conflict = self._requires_blocked_import(
                            spec, security.security_findings
                        )
                        if requirement_conflict:
                            fallback_reason = (
                                "the requirement mandates a blocked import; code-only repair "
                                "cannot satisfy both the requirement and security policy"
                            )
                            outcome = "blocked_requirement_conflict"
                    else:
                        outcome = "passed"
                except Exception as exc:
                    fallback_reason = "Coder repair could not complete sandbox or security checks"
                    errors.append(
                        redact_text(f"Coder verification {type(exc).__name__}: {exc}")
                    )

            if (coder_failed or fallback_reason) and not requirement_conflict:
                agents_used.append("debugger")
                debug_context = self._repair_context(
                    code=code,
                    tests=tests,
                    findings=security.security_findings,
                    attempt=attempt,
                    history=history,
                )
                debug_context["fallback_reason"] = fallback_reason
                try:
                    debug_patch = await self._debugger(
                        {
                            "report": self._redact(report.model_dump(mode="json")),
                            "code": self._redact(code.model_dump(mode="json")),
                            "spec": self._redact(spec),
                            "security_repair": debug_context,
                            "run_id": run_id,
                            "tenant_id": tenant_id,
                            "__engine_attempt__": attempt,
                        }
                    )
                    if not isinstance(debug_patch, DebugPatch):
                        raise TypeError("the Debugger did not return a DebugPatch")
                    modified_files = sorted(
                        set(modified_files) | set(self._debug_modified_files(debug_patch))
                    )
                    code = self._merge_debug(code, debug_patch)
                    report = await self._run_sandbox(
                        report=report,
                        code=code,
                        tests=tests,
                        spec=spec,
                        run_id=run_id,
                        tenant_id=tenant_id,
                        debug_patch=debug_patch,
                    )
                    security = await self._scan(report, spec)
                    if self._blocking(security):
                        outcome = "blocking_findings_remain"
                    elif report.exit_code != 0 or report.tests_failed > 0:
                        outcome = "security_clean_but_execution_or_tests_failed"
                    else:
                        outcome = "passed_after_debugger_fallback"
                except Exception as exc:
                    errors.append(redact_text(f"Debugger {type(exc).__name__}: {exc}"))
                    outcome = "debugger_fallback_failed"

            elapsed_ms = int((time.monotonic() - started) * 1000)
            models = self._models_since(run_id, records_before)
            final_agent = agents_used[-1]
            attempt_record = {
                "attempt": attempt,
                "agent": final_agent,
                "agents_used": agents_used,
                "models": models,
                "findings_before": findings_before,
                "findings_after": [
                    finding.model_dump(mode="json") for finding in security.security_findings
                ],
                "modified_files": modified_files,
                "latency_ms": elapsed_ms,
                "outcome": outcome,
                "fallback_reason": fallback_reason,
                "errors": errors,
            }
            safe_attempt = self._redact(attempt_record)
            if isinstance(safe_attempt, dict):
                attempt_record = safe_attempt
            history.append(attempt_record)
            self._record_attempt(
                run_id=run_id,
                tenant_id=tenant_id,
                code=code,
                context=context,
                record=attempt_record,
            )
            if not self._blocking(security):
                return security.model_copy(
                    update={"stderr": self._attempt_report(history, security.stderr)}
                )

        return security.model_copy(
            update={"stderr": self._attempt_report(history, security.stderr)}
        )

    async def _scan(self, report: ExecutionReport, spec: Any) -> ExecutionReport:
        try:
            result = await self._security_gate(
                {"report": report.model_dump(mode="json"), "spec": self._redact(spec)}
            )
            if not isinstance(result, ExecutionReport):
                raise TypeError("the security scanner did not return an ExecutionReport")
        except Exception as exc:
            return report.model_copy(
                update={
                    "command": "security_gate",
                    "security_findings": [
                        *report.security_findings,
                        SecurityFinding(
                            rule="SECURITY-SCAN-ERROR",
                            severity="high",
                            message=redact_text(
                                f"security scanner failed: {type(exc).__name__}: {exc}"
                            ),
                            tool="security-repair",
                        ),
                    ],
                }
            )
        result.security_findings = [
            finding.model_copy(update={"message": redact_text(finding.message)})
            for finding in result.security_findings
        ]
        has_scanner_error = any(
            "scanner-error" in finding.rule.lower() for finding in result.security_findings
        )
        if has_scanner_error and not self._blocking(result):
                result.security_findings.append(
                    SecurityFinding(
                        rule="SECURITY-SCAN-ERROR",
                        severity="high",
                        message="a security scanner could not complete; repair cannot pass closed",
                        tool="security-repair",
                    )
                )
        return result

    async def _run_sandbox(
        self,
        *,
        report: ExecutionReport,
        code: CodePatch,
        tests: TestSuite,
        spec: Any,
        run_id: str,
        tenant_id: str,
        debug_patch: DebugPatch | None = None,
    ) -> ExecutionReport:
        result = await self._sandbox_runner(
            {
                "code": code.model_dump(mode="json"),
                "tests": tests.model_dump(mode="json"),
                "spec": self._redact(spec),
                "run_id": run_id,
                "tenant_id": tenant_id,
                "report": report.model_dump(mode="json"),
                "patch": debug_patch.model_dump(mode="json") if debug_patch else None,
            }
        )
        if not isinstance(result, ExecutionReport):
            raise TypeError("the sandbox runner did not return an ExecutionReport")
        return result

    def _repair_context(
        self,
        *,
        code: CodePatch,
        tests: TestSuite,
        findings: list[SecurityFinding],
        attempt: int,
        history: list[dict[str, Any]],
    ) -> dict[str, Any]:
        source_files = {change.path: change.content for change in code.files}
        file_origins: dict[str, list[str]] = {
            change.path: ["coder: CodePatch"] for change in code.files
        }
        for test in tests.tests:
            test_path = _test_path(test.target_module)
            source_files[test_path] = test.test_code
            file_origins.setdefault(test_path, []).append("test_designer: TestSuite")
        finding_data: list[dict[str, Any]] = []
        for finding in findings:
            data = finding.model_dump(mode="json")
            data["description"] = finding.message
            remediation = getattr(finding, "remediation", None) or getattr(
                finding, "recommendation", None
            )
            if remediation:
                data["recommended_remediation"] = remediation
            finding_data.append(data)
        safe = self._redact(
            {
                "attempt": attempt,
                "maximum_attempts": self._max_attempts,
                "findings": finding_data,
                "source_files": source_files,
                "generated_file_origins": file_origins,
                "tests": tests.model_dump(mode="json"),
                "previous_attempts": history,
            }
        )
        return safe if isinstance(safe, dict) else {}

    @staticmethod
    def _blocking(report: ExecutionReport) -> bool:
        return any(finding.blocking for finding in report.security_findings)

    @staticmethod
    def _modified_files(before: CodePatch, after: CodePatch) -> list[str]:
        original = {change.path: change.content for change in before.files}
        current = {change.path: change.content for change in after.files}
        return sorted(
            path
            for path in original.keys() | current.keys()
            if original.get(path) != current.get(path)
        )

    @staticmethod
    def _debug_modified_files(patch: DebugPatch) -> list[str]:
        return [change.path for change in patch.proposed_changes]

    @staticmethod
    def _merge_debug(code: CodePatch, patch: DebugPatch) -> CodePatch:
        files = {change.path: change for change in code.files}
        for change in patch.proposed_changes:
            if change.operation == "delete":
                files.pop(change.path, None)
            else:
                files[change.path] = FileChange(
                    path=change.path,
                    operation=change.operation,
                    content=change.content,
                    sha256=change.sha256,
                )
        return code.model_copy(update={"files": list(files.values())})

    def _models_since(self, run_id: str, previous_ids: set[str]) -> dict[str, str]:
        records = [
            item
            for item in self._conversations.read_all()
            if item.call_id not in previous_ids and item.run_id == run_id
        ]
        return {
            role: max(
                (item for item in records if item.role == role),
                key=lambda item: item.timestamp,
            ).model
            for role in {item.role for item in records if item.role in {"coder", "debugger"}}
        }

    def _record_attempt(
        self,
        *,
        run_id: str,
        tenant_id: str,
        code: CodePatch,
        context: dict[str, Any],
        record: dict[str, Any],
    ) -> None:
        models = record["models"]
        model = models.get(record["agent"], "unknown")
        self._conversations.store(
            tenant_id=tenant_id,
            role="security_repair",
            model=model,
            attempt=int(record["attempt"]),
            latency_ms=int(record["latency_ms"]),
            run_id=run_id,
            prompt=json.dumps(context, ensure_ascii=False),
            response=json.dumps(
                {
                    "outcome": record["outcome"],
                    "modified_files": record["modified_files"],
                    "code": code.model_dump(mode="json"),
                    "findings_after": record["findings_after"],
                },
                ensure_ascii=False,
            ),
            error="; ".join(record["errors"]),
            metadata=self._redact(record),
        )

    @staticmethod
    def _attempt_report(history: list[dict[str, Any]], previous_stderr: str) -> str:
        attempts = "Security repair attempts: " + json.dumps(history, ensure_ascii=False)
        return f"{previous_stderr}\n{attempts}" if previous_stderr else attempts

    @staticmethod
    def _requires_blocked_import(spec: Any, findings: list[SecurityFinding]) -> bool:
        """Detect explicit requirements that mandate an import policy forbids."""
        if isinstance(spec, BaseModel):
            requirement = json.dumps(spec.model_dump(mode="json"), ensure_ascii=False)
        else:
            requirement = json.dumps(spec, ensure_ascii=False, default=str)
        lowered = requirement.lower()
        for finding in findings:
            if finding.rule != "S403-import-not-allowed":
                continue
            match = re.search(r"module '([^']+)'", finding.message)
            module = match.group(1) if match else ""
            if module not in BLOCKED_IMPORTS:
                continue
            mentions_module = re.search(rf"\b{re.escape(module)}\b", lowered)
            mandates_import = re.search(
                r"\b(must|required|requires|mandatory|use|using|import)\b", lowered
            )
            if mentions_module and mandates_import and re.search(
                rf"\b(import|use|using|requires?|must)\b.{{0,80}}\b{re.escape(module)}\b"
                rf"|\b{re.escape(module)}\b.{{0,80}}\b(import|use|required|must)\b",
                lowered,
            ):
                return True
        return False

    @staticmethod
    def _redact(value: Any) -> Any:
        return redact(value)
