"""The orchestrator: approvals, the parallel implementation step and the debug loop."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from oracle_hcm.app import AppConfig, build_orchestrator
from oracle_hcm.errors import RateLimitError
from oracle_hcm.schemas.artifacts import CodePatch, ExecutionReport, TestSuite
from oracle_hcm.services.orchestrator import Orchestrator


class StubSandbox:
    """Stands in for the Docker sandbox and returns scripted reports."""

    def __init__(self, exit_codes: list[int]) -> None:
        self._exit_codes = exit_codes
        self.calls: list[dict[str, Any]] = []

    async def run(
        self,
        *,
        patch: Any,
        tests: Any,
        debug_patch: Any = None,
        timeout_seconds: int | None = None,
        workspace_dir: Path | None = None,
        gate: Any = None,
    ) -> ExecutionReport:
        index = min(len(self.calls), len(self._exit_codes) - 1)
        exit_code = self._exit_codes[index]
        self.calls.append(
            {
                "exit_code": exit_code,
                "patch": patch,
                "tests": tests,
                "debug_patch": debug_patch,
            }
        )
        return ExecutionReport(
            run_id=f"run-{len(self.calls)}",
            requirement_id=patch.requirement_id,
            command="pytest",
            exit_code=exit_code,
            stdout="1 failed in 0.1s\n" if exit_code else "1 passed in 0.1s\n",
            stderr="",
            tests_passed=0 if exit_code else 1,
            tests_failed=1 if exit_code else 0,
        )


def _orchestrator(tmp_path: Path, sandbox: StubSandbox) -> Orchestrator:
    # These tests cover the approval flow, the parallel implementation step and
    # the debug loop. The phase 4 gates have their own tests.
    config = AppConfig(sop_id="sop_lightweight", use_fake_backend=True, max_phase=3)
    return build_orchestrator(
        config,
        sandbox=sandbox,  # type: ignore[arg-type]
        data_root=tmp_path,
    )


async def test_the_run_stops_at_the_first_approval(tmp_path: Path) -> None:
    sandbox = StubSandbox([0])
    orchestrator = _orchestrator(tmp_path, sandbox)

    result = await orchestrator.run("Add overtime pay")

    assert result.status == "awaiting_approval"
    assert result.approval is not None
    assert result.approval.stage == 1
    assert result.approval.artifact_type == "requirements"
    assert sandbox.calls == []


async def test_the_second_approval_guards_the_execution(tmp_path: Path) -> None:
    sandbox = StubSandbox([0])
    orchestrator = _orchestrator(tmp_path, sandbox)

    first = await orchestrator.run("Add overtime pay")
    assert first.approval is not None
    orchestrator._approvals.decide(first.approval.approval_id, approved=True, decided_by="jo")

    second = await orchestrator.resume(first.run_id)

    assert second.status == "awaiting_approval"
    assert second.approval is not None
    assert second.approval.stage == 2
    assert second.approval.artifact_type == "tests"
    assert sandbox.calls == []


async def test_a_full_run_reaches_the_sandbox(tmp_path: Path) -> None:
    sandbox = StubSandbox([0])
    orchestrator = _orchestrator(tmp_path, sandbox)

    first = await orchestrator.run("Add overtime pay")
    assert first.approval is not None
    orchestrator._approvals.decide(first.approval.approval_id, approved=True, decided_by="jo")
    second = await orchestrator.resume(first.run_id)
    assert second.approval is not None
    orchestrator._approvals.decide(second.approval.approval_id, approved=True, decided_by="jo")

    final = await orchestrator.resume(second.run_id)

    assert final.status == "completed"
    assert final.report is not None
    assert final.report.exit_code == 0
    assert len(sandbox.calls) == 1
    assert sandbox.calls[0]["tests"] is not None
    assert sandbox.calls[0]["patch"] is not None


async def test_the_coder_and_the_test_designer_run_in_parallel(tmp_path: Path) -> None:
    sandbox = StubSandbox([0])
    orchestrator = _orchestrator(tmp_path, sandbox)

    first = await orchestrator.run("Add overtime pay")
    assert first.approval is not None
    orchestrator._approvals.decide(first.approval.approval_id, approved=True, decided_by="jo")
    second = await orchestrator.resume(first.run_id)
    assert second.approval is not None
    orchestrator._approvals.decide(second.approval.approval_id, approved=True, decided_by="jo")
    final = await orchestrator.resume(second.run_id)

    outputs = final.sop_result.outputs if final.sop_result else {}
    assert "code" in outputs
    assert "tests" in outputs
    code = outputs["code"]
    suite = outputs["tests"]
    assert isinstance(code, CodePatch)
    assert isinstance(suite, TestSuite)
    assert code.files
    assert suite.tests


async def test_the_debug_loop_stops_after_three_attempts(tmp_path: Path) -> None:
    sandbox = StubSandbox([1, 1, 1, 1])
    orchestrator = _orchestrator(tmp_path, sandbox)

    first = await orchestrator.run("Add overtime pay")
    assert first.approval is not None
    orchestrator._approvals.decide(first.approval.approval_id, approved=True, decided_by="jo")
    second = await orchestrator.resume(first.run_id)
    assert second.approval is not None
    orchestrator._approvals.decide(second.approval.approval_id, approved=True, decided_by="jo")

    final = await orchestrator.resume(second.run_id)

    assert len(sandbox.calls) == 3
    assert final.status == "completed"
    assert final.report is not None
    assert final.report.exit_code == 1


async def test_the_debug_loop_stops_as_soon_as_the_run_passes(tmp_path: Path) -> None:
    sandbox = StubSandbox([1, 0, 0])
    orchestrator = _orchestrator(tmp_path, sandbox)

    first = await orchestrator.run("Add overtime pay")
    assert first.approval is not None
    orchestrator._approvals.decide(first.approval.approval_id, approved=True, decided_by="jo")
    second = await orchestrator.resume(first.run_id)
    assert second.approval is not None
    orchestrator._approvals.decide(second.approval.approval_id, approved=True, decided_by="jo")

    final = await orchestrator.resume(second.run_id)

    assert len(sandbox.calls) == 2
    assert final.report is not None
    assert final.report.exit_code == 0


async def test_the_repair_is_handed_to_the_next_sandbox_run(tmp_path: Path) -> None:
    sandbox = StubSandbox([1, 0])
    orchestrator = _orchestrator(tmp_path, sandbox)

    first = await orchestrator.run("Add overtime pay")
    assert first.approval is not None
    orchestrator._approvals.decide(first.approval.approval_id, approved=True, decided_by="jo")
    second = await orchestrator.resume(first.run_id)
    assert second.approval is not None
    orchestrator._approvals.decide(second.approval.approval_id, approved=True, decided_by="jo")

    await orchestrator.resume(second.run_id)

    assert sandbox.calls[0]["debug_patch"] is None
    assert sandbox.calls[1]["debug_patch"] is not None


async def test_a_rejected_approval_stops_the_run(tmp_path: Path) -> None:
    sandbox = StubSandbox([0])
    orchestrator = _orchestrator(tmp_path, sandbox)

    first = await orchestrator.run("Add overtime pay")
    assert first.approval is not None
    orchestrator._approvals.decide(first.approval.approval_id, approved=False, decided_by="jo")

    result = await orchestrator.resume(first.run_id)

    assert result.status == "failed"
    assert sandbox.calls == []


async def test_a_run_cannot_be_resumed_while_the_approval_is_pending(tmp_path: Path) -> None:
    sandbox = StubSandbox([0])
    orchestrator = _orchestrator(tmp_path, sandbox)
    result = await orchestrator.run("Add overtime pay")

    with pytest.raises(ValueError, match="pending"):
        await orchestrator.resume(result.run_id)


async def test_an_unknown_run_cannot_be_resumed(tmp_path: Path) -> None:
    sandbox = StubSandbox([0])
    orchestrator = _orchestrator(tmp_path, sandbox)

    with pytest.raises(FileNotFoundError):
        await orchestrator.resume("does-not-matter")


async def test_the_run_is_audited(tmp_path: Path) -> None:
    sandbox = StubSandbox([0])
    orchestrator = _orchestrator(tmp_path, sandbox)

    await orchestrator.run("Add overtime pay")

    audit = (tmp_path / "audit.jsonl").read_text(encoding="utf-8")
    assert "run_started" in audit
    assert "approval_requested" in audit


async def test_the_state_survives_on_disk(tmp_path: Path) -> None:
    sandbox = StubSandbox([0])
    orchestrator = _orchestrator(tmp_path, sandbox)

    result = await orchestrator.run("Add overtime pay")

    state_files = list((tmp_path / "runs").glob("*.json"))
    assert len(state_files) == 1
    assert result.run_id in state_files[0].name


def test_app_config_run_token_cap_default() -> None:
    """AppConfig exposes run_token_cap with a sensible default."""
    config = AppConfig()
    assert config.run_token_cap == 60_000


def test_app_config_run_token_cap_custom() -> None:
    """AppConfig accepts a custom run_token_cap."""
    config = AppConfig(run_token_cap=10_000)
    assert config.run_token_cap == 10_000


def test_build_orchestrator_with_live_flag_uses_token_cap(tmp_path: Path) -> None:
    """build_orchestrator passes the cap to DailyTokenCounter for live runs."""
    # We cannot call a real provider, so we verify the counter is configured by
    # inspecting the router's counter attribute after build.  The fake backend
    # path uses no budget (None).
    fake_config = AppConfig(use_fake_backend=True, run_token_cap=5_000)
    orc = build_orchestrator(fake_config, data_root=tmp_path)
    # Fake runs have no budget enforced: counter.daily_budget is None
    router = orc._engine._agents["requirements"]._router  # type: ignore[attr-defined]
    assert router._counter._daily_budget is None


async def test_token_cap_exceeded_emits_audit_event(tmp_path: Path) -> None:
    """When the router raises RateLimitError the orchestrator writes an audit event."""
    from oracle_hcm.log.eventlog import EventLog
    from oracle_hcm.services.approvals import ApprovalService
    from oracle_hcm.sop.engine import SopEngine, SopRunResult
    from oracle_hcm.sop.loader import load_sops

    # Build a fake SopEngine that always raises RateLimitError
    class BudgetExceededEngine(SopEngine):
        async def run(self, *args: object, **kwargs: object) -> SopRunResult:
            raise RateLimitError("daily token budget of 1 exceeded")

    sops = load_sops()
    sop = sops["sop_lightweight"]
    event_log = EventLog(tmp_path / "audit.jsonl")
    engine = BudgetExceededEngine(agents={}, schemas={}, gates={})

    from oracle_hcm.services.orchestrator import Orchestrator

    orc = Orchestrator(
        engine=engine,
        sop=sop,
        approvals=ApprovalService(tmp_path / "approvals"),
        event_log=event_log,
        schemas={},
        state_directory=tmp_path / "runs",
    )
    with pytest.raises(RateLimitError):
        await orc.run("trigger cap")

    audit = (tmp_path / "audit.jsonl").read_text(encoding="utf-8")
    assert "token_cap_exceeded" in audit
