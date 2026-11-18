"""The command line entry point."""

from __future__ import annotations

import getpass
from pathlib import Path

import pytest

from oracle_hcm import __main__ as cli
from oracle_hcm.api.users import ROLE_ADMIN, UserStore
from oracle_hcm.app import AppConfig
from oracle_hcm.services.approvals import ApprovalService
from oracle_hcm.services.orchestrator import OrchestrationResult
from oracle_hcm.sop.models import GateSpec

ADMIN_PASSWORD = "correct horse battery staple"


class StubOrchestrator:
    """Records what the CLI asked for."""

    def __init__(self) -> None:
        self.requests: list[str] = []
        self.resumed: list[str] = []

    async def run(self, request: str, *, tenant_id: str = "default") -> OrchestrationResult:
        self.requests.append(request)
        return OrchestrationResult(run_id="run-1", status="awaiting_approval")

    async def resume(self, run_id: str) -> OrchestrationResult:
        self.resumed.append(run_id)
        return OrchestrationResult(run_id=run_id, status="completed")


@pytest.fixture
def stub(monkeypatch: pytest.MonkeyPatch) -> StubOrchestrator:
    orchestrator = StubOrchestrator()
    monkeypatch.setattr(cli, "build_orchestrator", lambda config: orchestrator)
    return orchestrator


@pytest.fixture
def approvals(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> ApprovalService:
    service = ApprovalService(tmp_path)
    monkeypatch.setattr(cli, "_approvals", lambda: service)
    return service


def test_run_starts_a_run(stub: StubOrchestrator, capsys: pytest.CaptureFixture[str]) -> None:
    exit_code = cli.main(["run", "Add overtime pay"])

    assert exit_code == 1
    assert stub.requests == ["Add overtime pay"]
    assert "run_id: run-1" in capsys.readouterr().out


def test_resume_continues_a_run(stub: StubOrchestrator, capsys: pytest.CaptureFixture[str]) -> None:
    exit_code = cli.main(["resume", "run-1"])

    assert exit_code == 0
    assert stub.resumed == ["run-1"]
    assert "status: completed" in capsys.readouterr().out


def test_pending_lists_the_open_approvals(
    approvals: ApprovalService, capsys: pytest.CaptureFixture[str]
) -> None:
    exit_code = cli.main(["pending"])

    assert exit_code == 0
    assert "no pending approvals" in capsys.readouterr().out


def test_approve_records_the_decision(
    approvals: ApprovalService, capsys: pytest.CaptureFixture[str]
) -> None:
    request = approvals.request(
        run_id="run-1",
        gate=GateSpec(gate_id="g", type="admin_approval", params={"stage": 1}),
        artifact_type="requirements",
        artifact={"requirement_id": "REQ-1"},
    )

    exit_code = cli.main(["approve", request.approval_id])

    assert exit_code == 0
    stored = approvals.get(request.approval_id)
    assert stored is not None
    assert stored.status == "approved"
    assert "approved" in capsys.readouterr().out


def test_the_command_is_required() -> None:
    with pytest.raises(SystemExit):
        cli.main([])


def test_the_fake_backend_is_the_default() -> None:
    assert AppConfig().use_fake_backend is True


def test_create_admin_reads_the_password_from_the_terminal(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setenv("ORACLE_HCM_ROOT", str(tmp_path))
    monkeypatch.setattr(getpass, "getpass", lambda prompt="": ADMIN_PASSWORD)

    exit_code = cli.main(["create-admin", "--username", "admin", "--tenant", "t1"])

    assert exit_code == 0
    assert ADMIN_PASSWORD not in capsys.readouterr().out
    store = UserStore(tmp_path / "data" / "users.json")
    record = store.get("admin")
    assert record is not None
    assert record.role == ROLE_ADMIN
    assert record.tenant_id == "t1"
    assert record.password_hash.startswith("$argon2id$")
    assert ADMIN_PASSWORD not in store.path.read_text(encoding="utf-8")


def test_create_admin_refuses_two_different_passwords(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setenv("ORACLE_HCM_ROOT", str(tmp_path))
    answers = iter([ADMIN_PASSWORD, "a different long password"])
    monkeypatch.setattr(getpass, "getpass", lambda prompt="": next(answers))

    exit_code = cli.main(["create-admin", "--username", "admin"])

    assert exit_code == 1
    assert "do not match" in capsys.readouterr().out


def test_create_admin_takes_no_password_from_the_command_line() -> None:
    with pytest.raises(SystemExit):
        cli.main(["create-admin", "--username", "admin", "--password", "a-secret"])
