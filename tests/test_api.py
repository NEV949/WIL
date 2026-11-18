"""The HTTP gateway: users, sessions, roles, tenants and the stream."""

from __future__ import annotations

import asyncio
import json
import time
from collections.abc import AsyncIterator, Callable
from pathlib import Path
from typing import Any, cast

import httpx
import pytest
from starlette.testclient import TestClient

from oracle_hcm.api.auth import COOKIE_NAME, CSRF_HEADER
from oracle_hcm.api.gateway import ApiConfig, build_api
from oracle_hcm.api.tasks import TaskService, artifact_hash
from oracle_hcm.api.users import ROLE_ADMIN, ROLE_USER, UserStore
from oracle_hcm.config.models import load_model_registry
from oracle_hcm.config.settings import Settings
from oracle_hcm.log.access import AccessLog
from oracle_hcm.log.eventlog import EventLog
from oracle_hcm.services.approvals import ApprovalService
from oracle_hcm.signing.keys import generate_keypair, save_keypair
from oracle_hcm.signing.service import ArtifactSigner
from oracle_hcm.sop.models import GateSpec

PASSWORD = "correct horse battery staple"


def _gate() -> GateSpec:
    """The gate of the approvals of the tests."""
    return GateSpec(gate_id="admin_approval", type="admin_approval", params={"stage": 1})


class StubOrchestrator:
    """Stands in for the orchestrator: it records the runs and writes events."""

    def __init__(self, event_log: EventLog, root: Path) -> None:
        self._event_log = event_log
        self.state_directory = root / "runs"
        self.artifact_root = root / "artifacts"
        self.keys_directory = root / "keys"
        self.runs: list[dict[str, Any]] = []
        self.resumed: list[str] = []

    async def run(
        self,
        request: str,
        *,
        tenant_id: str = "default",
        run_id: str | None = None,
    ) -> str:
        self.runs.append({"request": request, "tenant_id": tenant_id, "run_id": run_id})
        assert run_id is not None
        self._event_log.append(
            tenant_id=tenant_id,
            actor="orchestrator",
            action="run_started",
            payload={"run_id": run_id, "sop_id": "sop_lightweight"},
        )
        return run_id

    async def resume(self, run_id: str) -> str:
        self.resumed.append(run_id)
        self._event_log.append(
            tenant_id="default",
            actor="orchestrator",
            action="run_resumed",
            payload={"run_id": run_id},
        )
        return run_id


@pytest.fixture
def api_env(tmp_path: Path) -> dict[str, Any]:
    """A gateway over a stub orchestrator, with two tenants."""
    return _build_env(tmp_path, ApiConfig(keep_alive_seconds=0.2))


def _build_env(tmp_path: Path, config: ApiConfig) -> dict[str, Any]:
    """The pieces of a gateway, over a stub orchestrator and two tenants."""
    event_log = EventLog(tmp_path / "audit.jsonl")
    approvals = ApprovalService(tmp_path / "approvals")
    access_log = AccessLog(tmp_path / "access.jsonl")
    users = UserStore(tmp_path / "users.json")
    users.create(user_id="admin", password=PASSWORD, role=ROLE_ADMIN, tenant_id="t1")
    users.create(user_id="bob", password=PASSWORD, role=ROLE_USER, tenant_id="t1")
    users.create(user_id="carol", password=PASSWORD, role=ROLE_USER, tenant_id="t2")
    users.create(user_id="dana", password=PASSWORD, role=ROLE_ADMIN, tenant_id="t2")
    settings = Settings.from_env({"JWT_SECRET": "a-test-secret-for-the-gateway-of-oracle-hcm"})
    orchestrator = StubOrchestrator(event_log, tmp_path)
    app = build_api(
        config=config,
        orchestrator=orchestrator,  # type: ignore[arg-type]
        event_log=event_log,
        approvals=approvals,
        access_log=access_log,
        users=users,
        settings=settings,
    )
    return {
        "app": app,
        "event_log": event_log,
        "approvals": approvals,
        "access_log": access_log,
        "users": users,
        "orchestrator": orchestrator,
        "root": tmp_path,
    }


@pytest.fixture
async def client(api_env: dict[str, Any]) -> AsyncIterator[httpx.AsyncClient]:
    """A client that talks to the gateway."""
    transport = httpx.ASGITransport(app=api_env["app"])
    async with httpx.AsyncClient(transport=transport, base_url="http://gateway") as client:
        yield client


@pytest.fixture
async def small_client(tmp_path: Path) -> AsyncIterator[httpx.AsyncClient]:
    """A client of a gateway that only accepts a small body."""
    env = _build_env(tmp_path, ApiConfig(max_request_bytes=512))
    transport = httpx.ASGITransport(app=env["app"])
    async with httpx.AsyncClient(transport=transport, base_url="http://gateway") as client:
        yield client


async def _login(
    client: httpx.AsyncClient, username: str = "admin", password: str = PASSWORD
) -> dict[str, Any]:
    """Open a session and return the body of the answer."""
    response = await client.post(
        "/auth/login", json={"username": username, "password": password}
    )
    assert response.status_code == 200, response.text
    return cast(dict[str, Any], response.json())


async def _wait_for(
    condition: Callable[[], bool], wait_seconds: float = 5.0
) -> None:
    """Wait until the condition holds."""
    deadline = time.monotonic() + wait_seconds
    while not condition():
        if time.monotonic() > deadline:
            raise AssertionError("the condition did not hold in time")
        await asyncio.sleep(0.01)


def _has_event(api_env: dict[str, Any], action: str) -> bool:
    """Whether the audit log holds an event with this action."""
    return any(event.action == action for event in api_env["event_log"].read_all())


def _headers(body: dict[str, Any]) -> dict[str, str]:
    return {CSRF_HEADER: str(body["csrf_token"])}


# --- the users ------------------------------------------------------------


def test_the_password_is_stored_as_an_argon2_hash(tmp_path: Path) -> None:
    store = UserStore(tmp_path / "users.json")
    record = store.create(user_id="jo", password=PASSWORD, role=ROLE_USER)

    assert record.password_hash.startswith("$argon2id$")
    assert PASSWORD not in record.password_hash
    assert PASSWORD not in store.path.read_text(encoding="utf-8")


def test_a_short_password_is_refused(tmp_path: Path) -> None:
    store = UserStore(tmp_path / "users.json")

    with pytest.raises(Exception, match="at least"):
        store.create(user_id="jo", password="short")


def test_the_wrong_password_does_not_authenticate(tmp_path: Path) -> None:
    store = UserStore(tmp_path / "users.json")
    store.create(user_id="jo", password=PASSWORD, role=ROLE_USER)

    assert store.authenticate("jo", "not the password") is None
    assert store.authenticate("jo", PASSWORD) is not None


def test_an_unknown_user_does_not_authenticate(tmp_path: Path) -> None:
    store = UserStore(tmp_path / "users.json")

    assert store.authenticate("nobody", PASSWORD) is None


# --- the login ------------------------------------------------------------


async def test_a_correct_login_opens_a_session(client: httpx.AsyncClient) -> None:
    body = await _login(client)

    assert body["user_id"] == "admin"
    assert body["role"] == ROLE_ADMIN
    assert body["tenant_id"] == "t1"
    assert body["csrf_token"]


async def test_the_session_cookie_is_http_only_and_strict(
    client: httpx.AsyncClient,
) -> None:
    response = await client.post(
        "/auth/login", json={"username": "admin", "password": PASSWORD}
    )

    cookie = response.headers.get("set-cookie", "")
    assert COOKIE_NAME in cookie
    assert "HttpOnly" in cookie
    assert "SameSite=strict" in cookie


async def test_authenticated_request_performs_sliding_session_renewal(
    client: httpx.AsyncClient,
) -> None:
    """An authenticated request performs sliding renewal of the session and cookie."""
    import asyncio

    login_resp = await client.post(
        "/auth/login", json={"username": "admin", "password": PASSWORD}
    )
    assert login_resp.status_code == 200
    first_cookie = login_resp.headers.get("set-cookie", "")
    assert COOKIE_NAME in first_cookie

    await asyncio.sleep(0.05)
    resp = await client.get("/approvals/pending")
    assert resp.status_code == 200
    renewed_cookie = resp.headers.get("set-cookie", "")
    assert COOKIE_NAME in renewed_cookie
    assert "HttpOnly" in renewed_cookie
    assert "SameSite=strict" in renewed_cookie


async def test_a_wrong_password_is_refused(client: httpx.AsyncClient) -> None:
    response = await client.post(
        "/auth/login", json={"username": "admin", "password": "wrong"}
    )

    assert response.status_code == 401
    assert response.json()["error"] == "unauthenticated"


async def test_an_unknown_user_is_refused(client: httpx.AsyncClient) -> None:
    response = await client.post(
        "/auth/login", json={"username": "nobody", "password": PASSWORD}
    )

    assert response.status_code == 401


async def test_the_answer_never_holds_the_password(
    client: httpx.AsyncClient, api_env: dict[str, Any]
) -> None:
    response = await client.post(
        "/auth/login", json={"username": "admin", "password": PASSWORD}
    )

    assert PASSWORD not in response.text
    record = api_env["users"].get("admin")
    assert record is not None
    assert record.password_hash not in response.text


async def test_the_account_locks_after_repeated_failures(
    client: httpx.AsyncClient,
) -> None:
    for _ in range(5):
        await client.post(
            "/auth/login", json={"username": "admin", "password": "wrong"}
        )

    response = await client.post(
        "/auth/login", json={"username": "admin", "password": PASSWORD}
    )

    assert response.status_code == 429
    assert response.json()["error"] == "account_locked"
    assert response.headers.get("retry-after")


async def test_a_locked_account_stays_locked_for_the_right_password(
    client: httpx.AsyncClient,
) -> None:
    for _ in range(6):
        await client.post(
            "/auth/login", json={"username": "bob", "password": "wrong"}
        )

    response = await client.post(
        "/auth/login", json={"username": "bob", "password": PASSWORD}
    )

    assert response.status_code == 429


async def test_a_request_without_a_session_is_refused(client: httpx.AsyncClient) -> None:
    response = await client.get("/tasks")

    assert response.status_code == 401


async def test_the_logout_closes_the_session(client: httpx.AsyncClient) -> None:
    body = await _login(client)

    response = await client.post("/auth/logout", headers=_headers(body))
    assert response.status_code == 200

    assert (await client.get("/tasks")).status_code == 401


# --- the roles ------------------------------------------------------------


async def test_a_plain_user_may_not_list_the_approvals(
    client: httpx.AsyncClient,
) -> None:
    body = await _login(client, "bob")

    response = await client.get("/approvals/pending")

    assert body["role"] == ROLE_USER
    assert response.status_code == 403
    assert response.json()["error"] == "forbidden"


async def test_an_admin_lists_the_approvals(client: httpx.AsyncClient) -> None:
    await _login(client, "admin")

    response = await client.get("/approvals/pending")

    assert response.status_code == 200
    assert response.json() == []


async def test_pending_risk_approval_is_reassociated_to_its_audited_run(
    client: httpx.AsyncClient, api_env: dict[str, Any]
) -> None:
    await _login(client, "admin")
    run_id = "1015b33bed12"
    stale_run_id = "run-REQ-PUNCH-001-PATCH-001-1794943950"
    api_env["event_log"].append(
        tenant_id="t1",
        actor="orchestrator",
        action="run_started",
        payload={"run_id": run_id, "sop_id": "sop_lightweight"},
    )
    risk_gate = GateSpec(
        gate_id="risk_tier",
        type="risk_tier",
        params={"stage": 0},
    )
    approval = api_env["approvals"].request(
        run_id=stale_run_id,
        gate=risk_gate,
        artifact_type="risk_assessment",
        artifact={"risk_tier": "high", "signals": ["keyword:payroll"]},
    )
    api_env["event_log"].append(
        tenant_id="t1",
        actor="orchestrator",
        action="approval_requested",
        payload={
            "run_id": run_id,
            "approval_id": approval.approval_id,
            "gate_id": "risk_tier",
            "stage": 0,
            "artifact_type": "risk_assessment",
        },
    )

    response = await client.get("/approvals/pending")

    assert response.status_code == 200
    assert response.json() == [
        {
            "approval_id": approval.approval_id,
            "run_id": run_id,
            "gate_id": "risk_tier",
            "stage": 0,
            "artifact_type": "risk_assessment",
            "status": "pending",
            "requested_at": approval.requested_at,
            "decided_at": None,
            "decided_by": None,
            "note": "",
            "artifact_hash": artifact_hash(approval.artifact),
        }
    ]
    persisted = api_env["approvals"].get(approval.approval_id)
    assert persisted is not None
    assert persisted.run_id == run_id
    assert persisted.tenant_id == "t1"


async def test_pending_approval_is_recovered_when_notification_event_is_missing(
    client: httpx.AsyncClient, api_env: dict[str, Any]
) -> None:
    await _login(client, "admin")
    approval = api_env["approvals"].request(
        run_id="notification-failed-run",
        tenant_id="t1",
        gate=GateSpec(gate_id="risk_tier", type="risk_tier", params={"stage": 0}),
        artifact_type="risk_assessment",
        artifact={"risk_tier": "high", "signals": ["keyword:payroll"]},
    )

    response = await client.get("/approvals/pending")

    assert response.status_code == 200
    assert [item["approval_id"] for item in response.json()] == [approval.approval_id]
    assert response.json()[0]["run_id"] == "notification-failed-run"


async def test_a_plain_user_may_not_decide_an_approval(
    client: httpx.AsyncClient, api_env: dict[str, Any]
) -> None:
    body = await _login(client, "bob")
    approval = api_env["approvals"].request(
        run_id="run-1",
        gate=_gate(),
        artifact_type="requirements",
        artifact={"summary": "add overtime"},
    )

    response = await client.post(
        f"/approvals/{approval.approval_id}/decide",
        json={
            "decision": "approved",
            "artifact_hash": artifact_hash(approval.artifact),
        },
        headers=_headers(body),
    )

    assert response.status_code == 403


# --- the CSRF token -------------------------------------------------------


async def test_a_state_changing_request_without_a_csrf_token_is_refused(
    client: httpx.AsyncClient,
) -> None:
    await _login(client)

    response = await client.post("/tasks", json={"request": "add overtime"})

    assert response.status_code == 403


async def test_a_state_changing_request_with_a_wrong_csrf_token_is_refused(
    client: httpx.AsyncClient,
) -> None:
    await _login(client)

    response = await client.post(
        "/tasks",
        json={"request": "add overtime"},
        headers={CSRF_HEADER: "not the token"},
    )

    assert response.status_code == 403


async def test_a_read_does_not_need_a_csrf_token(client: httpx.AsyncClient) -> None:
    await _login(client)

    response = await client.get("/tasks")

    assert response.status_code == 200


# --- the tasks ------------------------------------------------------------


async def test_a_task_is_submitted_and_the_orchestrator_runs_in_the_background(
    client: httpx.AsyncClient, api_env: dict[str, Any]
) -> None:
    body = await _login(client)

    response = await client.post(
        "/tasks", json={"request": "add overtime"}, headers=_headers(body)
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["tenant_id"] == "t1"
    assert payload["status"] == "running"
    await _wait_for(lambda: _has_event(api_env, "run_started"))
    assert api_env["orchestrator"].runs[0]["request"] == "add overtime"


async def test_the_tasks_are_listed_with_their_stage(
    client: httpx.AsyncClient, api_env: dict[str, Any]
) -> None:
    body = await _login(client)
    await client.post("/tasks", json={"request": "add overtime"}, headers=_headers(body))
    await _wait_for(lambda: _has_event(api_env, "run_started"))

    response = await client.get("/tasks")

    tasks = response.json()
    assert len(tasks) == 1
    assert tasks[0]["tenant_id"] == "t1"
    assert tasks[0]["status"] == "running"


async def test_a_task_of_another_tenant_is_not_found(
    client: httpx.AsyncClient, api_env: dict[str, Any]
) -> None:
    api_env["event_log"].append(
        tenant_id="t2",
        actor="orchestrator",
        action="run_started",
        payload={"run_id": "run-t2", "sop_id": "sop_lightweight"},
    )
    await _login(client, "admin", PASSWORD)

    response = await client.get("/tasks/run-t2")

    assert response.status_code == 404


async def test_the_events_of_a_task_are_its_own(
    client: httpx.AsyncClient, api_env: dict[str, Any]
) -> None:
    body = await _login(client)
    created = await client.post(
        "/tasks", json={"request": "add overtime"}, headers=_headers(body)
    )
    task_id = created.json()["task_id"]
    await _wait_for(lambda: _has_event(api_env, "run_started"))

    response = await client.get(f"/tasks/{task_id}/events")

    assert response.status_code == 200
    actions = [event["action"] for event in response.json()]
    assert "run_started" in actions


async def test_a_body_over_the_limit_is_refused(
    client: httpx.AsyncClient,
) -> None:
    body = await _login(client)

    response = await client.post(
        "/tasks", json={"request": "x" * 70_000}, headers=_headers(body)
    )

    assert response.status_code == 413
    assert response.json()["error"] == "payload_too_large"


async def test_a_small_limit_is_enforced(
    small_client: httpx.AsyncClient,
) -> None:
    body = await _login(small_client)

    response = await small_client.post(
        "/tasks", json={"request": "x" * 4096}, headers=_headers(body)
    )

    assert response.status_code == 413
    assert response.json()["error"] == "payload_too_large"


async def test_the_artifact_of_a_task_is_signed_and_verifies(
    client: httpx.AsyncClient, api_env: dict[str, Any]
) -> None:
    await _login(client)
    root = api_env["root"]
    keys = root / "keys"
    save_keypair(generate_keypair(), keys)
    workspace = root / "workspace"
    workspace.mkdir()
    (workspace / "main.py").write_text("print('hello')\n", encoding="utf-8")
    api_env["event_log"].append(
        tenant_id="t1",
        actor="orchestrator",
        action="run_started",
        payload={"run_id": "run-1", "sop_id": "sop_lightweight"},
    )
    signer = ArtifactSigner(
        registry=load_model_registry(),
        event_log=api_env["event_log"],
        artifact_root=root / "artifacts",
        keys_directory=keys,
    )
    signed = signer.sign_artifact(
        artifact_id="art-1",
        requirement_id="REQ-1",
        workspace=workspace,
        test_report={},
        security_report={},
        acceptance_result={},
        risk_tier="low",
        approvals=[],
        tenant_id="t1",
        run_id="run-1",
    )

    response = await client.get("/tasks/run-1/artifact")

    assert response.status_code == 200
    view = response.json()
    assert view["artifact_id"] == "art-1"
    assert view["manifest"]["root_hash"] == signed.manifest.root_hash
    assert view["verified"] is True
    assert [check["name"] for check in view["checks"]] == [
        "root_hash",
        "signature",
        "log_head",
    ]


async def test_the_artifact_of_another_tenant_is_not_found(
    client: httpx.AsyncClient, api_env: dict[str, Any]
) -> None:
    await _login(client, "carol")

    response = await client.get("/tasks/run-1/artifact")

    assert response.status_code == 404


# --- the tenants ----------------------------------------------------------


async def test_a_tenant_only_sees_its_own_tasks(
    client: httpx.AsyncClient, api_env: dict[str, Any]
) -> None:
    api_env["event_log"].append(
        tenant_id="t1",
        actor="orchestrator",
        action="run_started",
        payload={"run_id": "run-t1", "sop_id": "sop_lightweight"},
    )
    api_env["event_log"].append(
        tenant_id="t2",
        actor="orchestrator",
        action="run_started",
        payload={"run_id": "run-t2", "sop_id": "sop_lightweight"},
    )
    await _login(client, "carol")

    response = await client.get("/tasks")

    tasks = response.json()
    assert [task["tenant_id"] for task in tasks] == ["t2"]


async def test_the_metrics_are_the_ones_of_the_tenant(
    client: httpx.AsyncClient, api_env: dict[str, Any]
) -> None:
    api_env["event_log"].append(
        tenant_id="t1",
        actor="orchestrator",
        action="run_completed",
        payload={"run_id": "run-t1", "status": "completed"},
    )
    api_env["event_log"].append(
        tenant_id="t2",
        actor="orchestrator",
        action="run_failed",
        payload={"run_id": "run-t2", "status": "failed"},
    )
    await _login(client, "carol")

    response = await client.get("/metrics")

    metrics = response.json()
    assert metrics["tenant_id"] == "t2"
    assert metrics["tasks_total"] == 1
    assert metrics["tasks_failed"] == 1




def test_security_gate_findings_show_as_blocked_and_are_listed(
    tmp_path: Path,
) -> None:
    event_log = EventLog(tmp_path / "audit.jsonl")
    runs = tmp_path / "runs"
    runs.mkdir()
    run_id = "security-run"
    event_log.append(
        tenant_id="t1",
        actor="orchestrator",
        action="run_started",
        payload={"run_id": run_id, "sop_id": "sop_lightweight"},
    )
    event_log.append(
        tenant_id="t1",
        actor="orchestrator",
        action="step_completed",
        payload={"run_id": run_id, "step_id": "security_gate"},
    )
    event_log.append(
        tenant_id="t1",
        actor="orchestrator",
        action="run_failed",
        payload={
            "run_id": run_id,
            "status": "failed",
            "failure": "1 blocking security finding(s): S403-import-not-allowed app.py:4",
        },
    )
    (runs / f"{run_id}.json").write_text(
        json.dumps(
            {
                "status": "failed",
                "outputs": {
                    "security_gate": {
                        "security_findings": [
                            {
                                "rule": "S403-import-not-allowed",
                                "severity": "high",
                                "file": "app.py",
                                "line": 4,
                                "message": "module is not allowed",
                                "tool": "ast",
                            }
                        ]
                    }
                },
            }
        ),
        encoding="utf-8",
    )
    service = TaskService(
        event_log=event_log,
        approvals=ApprovalService(tmp_path / "approvals"),
        runs_directory=runs,
        artifact_root=tmp_path / "artifacts",
    )

    task = service.get_task(run_id, "t1")
    metrics = service.metrics("t1")

    assert task.status == "blocked"
    assert task.stage == "security"
    assert task.failure is not None
    assert metrics.tasks_failed == 0
    assert metrics.tasks_blocked == 1
    assert metrics.security_details[0].rule == "S403-import-not-allowed"
    assert metrics.security_details[0].file == "app.py"
    assert metrics.security_findings[0].count == 1


# --- the approvals --------------------------------------------------------


async def test_an_approval_is_decided_with_the_hash_of_the_artifact(
    client: httpx.AsyncClient, api_env: dict[str, Any]
) -> None:
    body = await _login(client, "admin")
    api_env["event_log"].append(
        tenant_id="t1",
        actor="orchestrator",
        action="run_started",
        payload={"run_id": "run-1", "sop_id": "sop_lightweight"},
    )
    approval = api_env["approvals"].request(
        run_id="run-1",
        gate=_gate(),
        artifact_type="requirements",
        artifact={"summary": "add overtime"},
    )

    response = await client.post(
        f"/approvals/{approval.approval_id}/decide",
        json={
            "decision": "approved",
            "comment": "looks right",
            "artifact_hash": artifact_hash(approval.artifact),
        },
        headers=_headers(body),
    )

    assert response.status_code == 200
    view = response.json()
    assert view["status"] == "approved"
    assert view["decided_by"] == "admin"
    assert view["note"] == "looks right"
    assert view["artifact_hash"] == artifact_hash(approval.artifact)
    await _wait_for(lambda: bool(api_env["orchestrator"].resumed))
    assert api_env["orchestrator"].resumed == ["run-1"]


async def test_an_approval_is_refused_when_the_artifact_changed(
    client: httpx.AsyncClient, api_env: dict[str, Any]
) -> None:
    body = await _login(client, "admin")
    api_env["event_log"].append(
        tenant_id="t1",
        actor="orchestrator",
        action="run_started",
        payload={"run_id": "run-1", "sop_id": "sop_lightweight"},
    )
    approval = api_env["approvals"].request(
        run_id="run-1",
        gate=_gate(),
        artifact_type="requirements",
        artifact={"summary": "add overtime"},
    )

    response = await client.post(
        f"/approvals/{approval.approval_id}/decide",
        json={"decision": "approved", "artifact_hash": "0" * 64},
        headers=_headers(body),
    )

    assert response.status_code == 409
    assert api_env["approvals"].get(approval.approval_id) is not None
    assert api_env["approvals"].get(approval.approval_id).status == "pending"


async def test_the_decision_is_audited(
    client: httpx.AsyncClient, api_env: dict[str, Any]
) -> None:
    body = await _login(client, "admin")
    api_env["event_log"].append(
        tenant_id="t1",
        actor="orchestrator",
        action="run_started",
        payload={"run_id": "run-1", "sop_id": "sop_lightweight"},
    )
    approval = api_env["approvals"].request(
        run_id="run-1",
        gate=_gate(),
        artifact_type="requirements",
        artifact={"summary": "add overtime"},
    )

    await client.post(
        f"/approvals/{approval.approval_id}/decide",
        json={
            "decision": "approved",
            "artifact_hash": artifact_hash(approval.artifact),
        },
        headers=_headers(body),
    )

    events = api_env["event_log"].read_all()
    decided = [event for event in events if event.action == "approval_decided"]
    assert len(decided) == 1
    assert decided[0].actor == "admin"
    assert decided[0].payload["decision"] == "approved"


async def test_an_approval_of_another_tenant_is_not_found(
    client: httpx.AsyncClient, api_env: dict[str, Any]
) -> None:
    body = await _login(client, "dana")
    api_env["event_log"].append(
        tenant_id="t1",
        actor="orchestrator",
        action="run_started",
        payload={"run_id": "run-t1", "sop_id": "sop_lightweight"},
    )
    approval = api_env["approvals"].request(
        run_id="run-t1",
        gate=_gate(),
        artifact_type="requirements",
        artifact={"summary": "add overtime"},
    )

    response = await client.post(
        f"/approvals/{approval.approval_id}/decide",
        json={
            "decision": "approved",
            "artifact_hash": artifact_hash(approval.artifact),
        },
        headers=_headers(body),
    )

    assert response.status_code == 404
    assert api_env["approvals"].get(approval.approval_id).status == "pending"


async def test_a_plain_user_of_another_tenant_may_not_decide_an_approval(
    client: httpx.AsyncClient, api_env: dict[str, Any]
) -> None:
    body = await _login(client, "carol")
    approval = api_env["approvals"].request(
        run_id="run-t1",
        gate=_gate(),
        artifact_type="requirements",
        artifact={"summary": "add overtime"},
    )

    response = await client.post(
        f"/approvals/{approval.approval_id}/decide",
        json={
            "decision": "approved",
            "artifact_hash": artifact_hash(approval.artifact),
        },
        headers=_headers(body),
    )

    assert response.status_code == 403
    assert api_env["approvals"].get(approval.approval_id).status == "pending"


# --- the stream -----------------------------------------------------------


def test_the_stream_only_carries_the_events_of_the_tenant(
    api_env: dict[str, Any],
) -> None:
    app = api_env["app"]
    with TestClient(app) as client:
        login = client.post("/auth/login", json={"username": "carol", "password": PASSWORD})
        assert login.status_code == 200

        api_env["event_log"].append(
            tenant_id="t2", actor="orchestrator", action="for_t2", payload={}
        )
        api_env["event_log"].append(
            tenant_id="t1", actor="orchestrator", action="for_t1", payload={}
        )
        app.state.gateway.stream.poll()

        received: list[dict[str, Any]] = []
        with client.stream("GET", "/events/stream?since=0") as response:
            assert response.status_code == 200
            assert response.headers["content-type"].startswith("text/event-stream")
            for line in response.iter_lines():
                if line.startswith("data: "):
                    received.append(json.loads(line[6:]))
                    break

    assert [event["action"] for event in received] == ["for_t2"]
    assert all(event["tenant_id"] == "t2" for event in received)


async def test_the_stream_refuses_a_caller_without_a_session(
    client: httpx.AsyncClient,
) -> None:
    response = await client.get("/events/stream")

    assert response.status_code == 401


# --- the access log -------------------------------------------------------


async def test_the_access_log_holds_the_logins(
    client: httpx.AsyncClient, api_env: dict[str, Any]
) -> None:
    await _login(client, "admin")
    await client.post(
        "/auth/login", json={"username": "admin", "password": "wrong"}
    )

    entries = api_env["access_log"].read_all()
    assert [entry.result for entry in entries] == ["success", "failure"]
    assert entries[0].user_id == "admin"
    assert entries[0].tenant_id == "t1"
    assert entries[0].action == "login"
    assert entries[0].correlation_id


async def test_the_access_log_chain_verifies(
    client: httpx.AsyncClient, api_env: dict[str, Any]
) -> None:
    await _login(client, "admin")
    await _login(client, "bob")

    assert api_env["access_log"].verify() is True


async def test_a_tampered_access_log_breaks_the_chain(
    client: httpx.AsyncClient, api_env: dict[str, Any]
) -> None:
    await _login(client, "admin")
    path = api_env["access_log"].path
    lines = path.read_text(encoding="utf-8").splitlines()
    payload = json.loads(lines[0])
    payload["user_id"] = "someone else"
    lines[0] = json.dumps(payload)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    assert api_env["access_log"].verify() is False


async def test_the_access_log_carries_the_approvals(
    client: httpx.AsyncClient, api_env: dict[str, Any]
) -> None:
    body = await _login(client, "admin")
    api_env["event_log"].append(
        tenant_id="t1",
        actor="orchestrator",
        action="run_started",
        payload={"run_id": "run-1", "sop_id": "sop_lightweight"},
    )
    approval = api_env["approvals"].request(
        run_id="run-1",
        gate=_gate(),
        artifact_type="requirements",
        artifact={"summary": "add overtime"},
    )

    await client.post(
        f"/approvals/{approval.approval_id}/decide",
        json={
            "decision": "approved",
            "artifact_hash": artifact_hash(approval.artifact),
        },
        headers=_headers(body),
    )

    entries = api_env["access_log"].read_all()
    approvals = [entry for entry in entries if entry.action == "approval"]
    assert len(approvals) == 1
    assert approvals[0].result == "success"
    assert approvals[0].user_id == "admin"


# --- the guards -----------------------------------------------------------


async def test_the_security_headers_are_on_every_answer(
    client: httpx.AsyncClient,
) -> None:
    response = await client.get("/health")

    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "no-referrer"
    assert "no-store" in response.headers["cache-control"]


async def test_the_health_endpoint_needs_no_session(client: httpx.AsyncClient) -> None:
    response = await client.get("/health")

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


# --- the console static files ---------------------------------------------


async def test_the_gateway_serves_the_console_shell(tmp_path: Path) -> None:
    dist = tmp_path / "dist"
    dist.mkdir()
    (dist / "index.html").write_text("<!doctype html><title>Console</title>", encoding="utf-8")
    env = _build_env(tmp_path, ApiConfig(web_dist=dist))
    transport = httpx.ASGITransport(app=env["app"])
    async with httpx.AsyncClient(transport=transport, base_url="http://gateway") as client:
        response = await client.get("/")
        assert response.status_code == 200
        assert "<title>Console</title>" in response.text
        assert "default-src 'self'" in response.headers["content-security-policy"]
        assert "no-store" in response.headers["cache-control"]


async def test_the_gateway_serves_spa_routes_with_the_shell(tmp_path: Path) -> None:
    dist = tmp_path / "dist"
    dist.mkdir()
    (dist / "index.html").write_text("<!doctype html><title>Console</title>", encoding="utf-8")
    env = _build_env(tmp_path, ApiConfig(web_dist=dist))
    transport = httpx.ASGITransport(app=env["app"])
    async with httpx.AsyncClient(transport=transport, base_url="http://gateway") as client:
        response = await client.get("/approvals")
        assert response.status_code == 200
        assert "<title>Console</title>" in response.text


async def test_the_gateway_serves_hashed_assets_with_immutable_cache(tmp_path: Path) -> None:
    dist = tmp_path / "dist"
    assets = dist / "assets"
    assets.mkdir(parents=True)
    (dist / "index.html").write_text("<!doctype html>", encoding="utf-8")
    (assets / "bundle.12345.js").write_text("console.log('ok');", encoding="utf-8")
    env = _build_env(tmp_path, ApiConfig(web_dist=dist))
    transport = httpx.ASGITransport(app=env["app"])
    async with httpx.AsyncClient(transport=transport, base_url="http://gateway") as client:
        response = await client.get("/assets/bundle.12345.js")
        assert response.status_code == 200
        assert "console.log" in response.text
        assert "immutable" in response.headers["cache-control"]

