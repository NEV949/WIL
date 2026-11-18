"""Security feedback and bounded agentic repair loop."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from oracle_hcm.log.conversation import ConversationStore
from oracle_hcm.schemas.artifacts import (
    CodePatch,
    DebugPatch,
    ExecutionReport,
    FileChange,
    SecurityFinding,
    TestCase,
    TestSuite,
)
from oracle_hcm.services.acceptance import SecurityCleanGate
from oracle_hcm.services.security_repair import SecurityRepairAgent
from oracle_hcm.sop.engine import SopEngine
from oracle_hcm.sop.models import GateSpec, SopDefinition, SopStep


def _finding() -> SecurityFinding:
    return SecurityFinding(
        rule="S777-example-rule",
        severity="high",
        file="src/service.py",
        line=1,
        message="unsafe import; remove the import and implement with an approved module",
        tool="ast",
    )


def _code(source: str = "import unsafe_module\n") -> CodePatch:
    return CodePatch(
        patch_id="PATCH-1",
        requirement_id="REQ-1",
        files=[FileChange(path="src/service.py", operation="create", content=source)],
    )


def _tests() -> TestSuite:
    return TestSuite(
        suite_id="SUITE-1",
        requirement_id="REQ-1",
        tests=[
            TestCase(
                test_id="T-1",
                requirement_ids=["REQ-1"],
                target_module="src.service",
                test_code="def test_service(): assert True",
            )
        ],
    )


def _report(
    *, findings: list[SecurityFinding] | None = None, exit_code: int = 0
) -> ExecutionReport:
    return ExecutionReport(
        run_id="RUN-1",
        requirement_id="REQ-1",
        command="pytest",
        exit_code=exit_code,
        security_findings=findings or [],
        workspace_path="workspace",
    )


def _log_model_call(store: ConversationStore, role: str, run_id: str) -> None:
    store.store(
        tenant_id="tenant-a",
        role=role,
        model=f"fake/{role}",
        run_id=run_id,
        prompt="repair prompt",
        response="repair response",
    )


def _repair_agent(
    tmp_path: Path,
    *,
    coder: Any,
    debugger: Any,
    sandbox: Any,
    scanner: Any,
    max_attempts: int = 3,
) -> tuple[SecurityRepairAgent, ConversationStore]:
    store = ConversationStore(tmp_path / "conversations")
    return (
        SecurityRepairAgent(
            coder=coder,
            debugger=debugger,
            sandbox_runner=sandbox,
            security_gate=scanner,
            conversations=store,
            max_attempts=max_attempts,
        ),
        store,
    )


def _sandbox_for_content(*, findings_if_unsafe: bool = True) -> Any:
    async def sandbox(payload: dict[str, Any]) -> ExecutionReport:
        code = CodePatch.model_validate(payload["code"])
        patch = payload.get("patch")
        debug = DebugPatch.model_validate(patch) if patch else None
        content = "\n".join(change.content for change in code.files)
        if debug is not None:
            content += "\n" + "\n".join(
                change.content for change in debug.proposed_changes
            )
        findings = [_finding()] if findings_if_unsafe and "unsafe_module" in content else []
        return _report(findings=findings)

    return sandbox


def _passthrough_scanner() -> Any:
    async def scan(payload: dict[str, Any]) -> ExecutionReport:
        report = ExecutionReport.model_validate(payload["report"])
        return report.model_copy(update={"command": "security_gate"})

    return scan


async def test_security_findings_are_sent_to_coder_and_a_clean_repair_is_rescanned(
    tmp_path: Path,
) -> None:
    seen: list[dict[str, Any]] = []
    store = ConversationStore(tmp_path / "calls")

    async def coder(payload: dict[str, Any]) -> CodePatch:
        seen.append(payload)
        _log_model_call(store, "coder", "RUN-1")
        return _code("SAFE = True\n")

    async def debugger(payload: dict[str, Any]) -> DebugPatch:
        raise AssertionError("Debugger is only a fallback")

    scan_count = 0

    async def scanner(payload: dict[str, Any]) -> ExecutionReport:
        nonlocal scan_count
        scan_count += 1
        scanned = await _passthrough_scanner()(payload)
        assert isinstance(scanned, ExecutionReport)
        return scanned

    agent, store = _repair_agent(
        tmp_path,
        coder=coder,
        debugger=debugger,
        sandbox=_sandbox_for_content(),
        scanner=scanner,
    )
    result = await agent(
        {
            "report": _report(findings=[_finding()]),
            "code": _code(),
            "tests": _tests(),
            "spec": {"description": "preserve the required service behavior"},
            "run_id": "RUN-1",
            "tenant_id": "tenant-a",
        }
    )

    assert seen[0]["security_repair"]["findings"][0]["rule"] == "S777-example-rule"
    assert seen[0]["security_repair"]["findings"][0]["severity"] == "high"
    assert seen[0]["security_repair"]["findings"][0]["file"] == "src/service.py"
    assert seen[0]["security_repair"]["findings"][0]["line"] == 1
    assert "unsafe_module" in seen[0]["current_code"]["src/service.py"]
    assert seen[0]["security_repair"]["generated_file_origins"]["src/service.py"] == [
        "coder: CodePatch"
    ]
    assert result.security_findings == []
    assert scan_count == 2
    attempt_records = [item for item in store.read_all() if item.role == "security_repair"]
    assert len(attempt_records) == 1
    assert attempt_records[0].model == "fake/coder"
    assert attempt_records[0].latency_ms >= 0
    assert attempt_records[0].attempt == 1
    assert attempt_records[0].metadata["outcome"] == "passed"


async def test_coder_failure_invokes_debugger_fallback(tmp_path: Path) -> None:
    calls: list[str] = []
    store = ConversationStore(tmp_path / "calls")

    async def coder(payload: dict[str, Any]) -> CodePatch:
        calls.append("coder")
        _log_model_call(store, "coder", "RUN-1")
        raise RuntimeError("coder unavailable")

    async def debugger(payload: dict[str, Any]) -> DebugPatch:
        calls.append("debugger")
        assert "S777-example-rule" in json.dumps(payload["security_repair"])
        _log_model_call(store, "debugger", "RUN-1")
        return DebugPatch(
            patch_id="DEBUG-1",
            requirement_id="REQ-1",
            attempt=1,
            proposed_changes=[
                FileChange(path="src/service.py", operation="modify", content="SAFE = True\n")
            ],
        )

    agent, store = _repair_agent(
        tmp_path,
        coder=coder,
        debugger=debugger,
        sandbox=_sandbox_for_content(),
        scanner=_passthrough_scanner(),
    )
    result = await agent(
        {
            "report": _report(findings=[_finding()]),
            "code": _code(),
            "tests": _tests(),
            "run_id": "RUN-1",
        }
    )

    assert calls == ["coder", "debugger"]
    assert result.security_findings == []
    record = next(item for item in store.read_all() if item.role == "security_repair")
    assert record.metadata["agents_used"] == ["coder", "debugger"]
    assert record.metadata["models"]["debugger"] == "fake/debugger"


async def test_requirement_mandating_a_blocked_import_fails_without_debugger(
    tmp_path: Path,
) -> None:
    calls: list[str] = []
    blocked = SecurityFinding(
        rule="S403-import-not-allowed",
        severity="high",
        file="src/service.py",
        line=1,
        message="the module 'paramiko' is not on the import allowlist",
        tool="ast",
    )

    async def coder(payload: dict[str, Any]) -> CodePatch:
        calls.append("coder")
        return _code("import paramiko\n")

    async def debugger(payload: dict[str, Any]) -> DebugPatch:
        calls.append("debugger")
        raise AssertionError("requirement conflicts must fail without asking the Debugger")

    async def sandbox(payload: dict[str, Any]) -> ExecutionReport:
        return _report(findings=[blocked])

    agent, _ = _repair_agent(
        tmp_path,
        coder=coder,
        debugger=debugger,
        sandbox=sandbox,
        scanner=_passthrough_scanner(),
        max_attempts=1,
    )
    result = await agent(
        {
            "report": _report(findings=[blocked]),
            "code": _code("import paramiko\n"),
            "tests": _tests(),
            "spec": {"description": "The implementation must import paramiko to connect."},
            "run_id": "RUN-1",
        }
    )

    assert calls == ["coder"]
    assert result.security_findings == [blocked]
    assert "requirement mandates a blocked import" in result.stderr


async def test_failed_findings_and_latest_code_are_in_the_next_retry_prompt(
    tmp_path: Path,
) -> None:
    coder_contexts: list[dict[str, Any]] = []
    store = ConversationStore(tmp_path / "calls")

    async def coder(payload: dict[str, Any]) -> CodePatch:
        coder_contexts.append(payload["security_repair"])
        _log_model_call(store, "coder", "RUN-1")
        return _code()

    async def debugger(payload: dict[str, Any]) -> DebugPatch:
        _log_model_call(store, "debugger", "RUN-1")
        return DebugPatch(
            patch_id="DEBUG-1",
            requirement_id="REQ-1",
            attempt=1,
            proposed_changes=[
                FileChange(
                    path="src/service.py",
                    operation="modify",
                    content="import unsafe_module\n",
                )
            ],
        )

    agent, store = _repair_agent(
        tmp_path,
        coder=coder,
        debugger=debugger,
        sandbox=_sandbox_for_content(),
        scanner=_passthrough_scanner(),
        max_attempts=2,
    )
    result = await agent(
        {
            "report": _report(findings=[_finding()]),
            "code": _code(),
            "tests": _tests(),
            "run_id": "RUN-1",
        }
    )

    assert len(coder_contexts) == 2
    assert coder_contexts[1]["attempt"] == 2
    assert coder_contexts[1]["previous_attempts"][0]["outcome"] == "blocking_findings_remain"
    assert coder_contexts[1]["findings"][0]["rule"] == "S777-example-rule"
    assert "unsafe_module" in coder_contexts[1]["source_files"]["src/service.py"]
    assert any(item.blocking for item in result.security_findings)
    assert "Security repair attempts" in result.stderr
    assert len([item for item in store.read_all() if item.role == "security_repair"]) == 2


async def test_repair_loop_stops_at_configured_retry_limit(tmp_path: Path) -> None:
    coder_calls = 0
    debugger_calls = 0

    async def coder(payload: dict[str, Any]) -> CodePatch:
        nonlocal coder_calls
        coder_calls += 1
        raise RuntimeError("coder failed")

    async def debugger(payload: dict[str, Any]) -> DebugPatch:
        nonlocal debugger_calls
        debugger_calls += 1
        raise RuntimeError("debugger failed")

    agent, _ = _repair_agent(
        tmp_path,
        coder=coder,
        debugger=debugger,
        sandbox=_sandbox_for_content(),
        scanner=_passthrough_scanner(),
        max_attempts=2,
    )
    result = await agent(
        {
            "report": _report(findings=[_finding()]),
            "code": _code(),
            "tests": _tests(),
            "run_id": "RUN-1",
        }
    )

    assert coder_calls == 2
    assert debugger_calls == 2
    assert len(result.security_findings) == 1
    attempts = json.loads(result.stderr.removeprefix("Security repair attempts: "))
    assert [item["attempt"] for item in attempts] == [1, 2]


async def test_security_clean_gate_cannot_be_bypassed_after_repair_failure() -> None:
    blocking_report = _report(findings=[_finding()])
    gate = SecurityCleanGate()
    outcome = await gate.evaluate(
        GateSpec(gate_id="security_clean", type="security_clean"),
        {"outputs": {"security_gate": blocking_report}},
    )
    assert outcome.status == "failed"
    assert "S777-example-rule" in outcome.detail


async def test_blocking_findings_stop_before_approval_or_deployment_steps() -> None:
    calls: list[str] = []

    async def security_agent(payload: dict[str, Any]) -> ExecutionReport:
        return _report(findings=[_finding()])

    async def downstream(payload: dict[str, Any]) -> ExecutionReport:
        calls.append("downstream")
        return _report()

    security_step = SopStep(
        step_id="security_gate",
        agent="security",
        output_schema="ExecutionReport",
        gates=[GateSpec(gate_id="security_clean", type="security_clean")],
    )
    approval_step = SopStep(
        step_id="approval",
        agent="approval",
        output_schema="ExecutionReport",
    )
    deployment_step = SopStep(
        step_id="deployment",
        agent="deployment",
        output_schema="ExecutionReport",
        phase=5,
    )
    engine = SopEngine(
        agents={"security": security_agent, "approval": downstream, "deployment": downstream},
        schemas={"ExecutionReport": ExecutionReport},
        gates={"security_clean": SecurityCleanGate()},
    )

    result = await engine.run(
        SopDefinition(
            sop_id="test",
            name="Security test",
            steps=[security_step, approval_step, deployment_step],
        ),
        {},
        max_phase=5,
    )

    assert result.status == "failed"
    assert calls == []
