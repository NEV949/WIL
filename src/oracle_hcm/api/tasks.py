"""The tasks of the gateway.

A task is a run of the orchestrator. The gateway never keeps a second copy
of its state: everything it shows is derived from the audit log and from the
state file of the run, so the view can never drift away from what happened.

The current stage of a task is derived from its events, as the specification
asks for.
"""

from __future__ import annotations

import json
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from oracle_hcm.api.errors import NotFoundError
from oracle_hcm.api.models import (
    ApprovalView,
    ArtifactView,
    ManifestCheck,
    MetricsView,
    RolloutState,
    SecurityFindingCount,
    SecurityFindingView,
    TaskEventView,
    TaskSummary,
    TaskView,
    TokenUsage,
)
from oracle_hcm.canonical import canonical_bytes, sha256_hex
from oracle_hcm.log.conversation import ConversationStore
from oracle_hcm.log.eventlog import EventLog
from oracle_hcm.paths import keys_dir
from oracle_hcm.schemas.events import AuditEvent
from oracle_hcm.services.approvals import ApprovalRequest, ApprovalService
from oracle_hcm.signing.keys import PUBLIC_KEY_NAME, load_public_key
from oracle_hcm.signing.manifest import (
    SignedManifest,
    signature_payload,
    verify_manifest,
)
from oracle_hcm.signing.service import load_signed_manifest
from oracle_hcm.signing.signer import Verifier

__all__ = [
    "TaskService",
    "artifact_hash",
    "current_stage",
]

SEVERITIES = ("critical", "high", "medium", "low")


def artifact_hash(artifact: dict[str, Any]) -> str:
    """The hash of the exact artifact an approval is about."""
    return sha256_hex(canonical_bytes(artifact))


@dataclass
class _Task:
    """The state of one task, folded from its events."""

    task_id: str
    tenant_id: str
    sop_id: str = ""
    status: str = "running"
    stage: str = "started"
    stage_number: int = 0
    created_at: str = ""
    updated_at: str = ""
    attempts: int = 0
    approval_id: str | None = None
    approval_status: str | None = None
    approval_stage: int | None = None
    failure: str | None = None
    steps: list[str] = field(default_factory=list)


def current_stage(events: Iterable[AuditEvent]) -> tuple[str, str, int]:
    """The status, the stage and the number of the stage of a run.

    The stage is derived from the events of the run, never from a counter
    that the gateway keeps on its own.
    """
    status = "running"
    stage = "started"
    stage_number = 0
    approval: tuple[str, int] | None = None
    for event in events:
        action = event.action
        if action == "run_started":
            stage = "requirements"
        elif action == "step_completed":
            stage = str(event.payload.get("step_id", stage))
        elif action == "approval_requested":
            approval = (
                str(event.payload.get("artifact_type", stage)),
                int(event.payload.get("stage", 0)),
            )
        elif action == "run_resumed":
            approval = None
        elif action == "run_completed":
            status = "completed"
        elif action == "run_failed":
            failure = str(event.payload.get("failure", ""))
            if "blocking security finding(s):" in failure:
                status = "blocked"
                stage = "security"
            else:
                status = "failed"
    if approval is not None:
        return "awaiting_approval", approval[0], approval[1]
    if status in ("completed", "failed"):
        return status, status, stage_number
    return status, stage, stage_number


class TaskService:
    """Reads the tasks of a tenant out of the audit log."""

    def __init__(
        self,
        *,
        event_log: EventLog,
        approvals: ApprovalService,
        runs_directory: Path,
        artifact_root: Path,
        conversation_store: ConversationStore | None = None,
        keys_directory: Path | None = None,
    ) -> None:
        self._event_log = event_log
        self._approvals = approvals
        self._runs_directory = runs_directory
        self._artifact_root = artifact_root
        self._conversations = conversation_store
        self._keys_directory = keys_directory if keys_directory is not None else keys_dir()

    # --- the tasks ------------------------------------------------------

    def _events(self) -> list[AuditEvent]:
        return self._event_log.read_all()

    def _grouped(self, tenant_id: str | None = None) -> dict[str, list[AuditEvent]]:
        """The events of every run, grouped by run id."""
        grouped: dict[str, list[AuditEvent]] = {}
        for event in self._events():
            if tenant_id is not None and event.tenant_id != tenant_id:
                continue
            run_id = str(event.payload.get("run_id", ""))
            if not run_id:
                continue
            grouped.setdefault(run_id, []).append(event)
        return grouped

    def _task(self, task_id: str, events: list[AuditEvent]) -> _Task:
        task = _Task(task_id=task_id, tenant_id=events[0].tenant_id)
        attempts = 0
        steps: list[str] = []
        approval_id: str | None = None
        approval_status: str | None = None
        approval_stage: int | None = None
        failure: str | None = None
        for event in events:
            task.updated_at = event.timestamp
            if event.action == "run_started":
                task.created_at = event.timestamp
                task.sop_id = str(event.payload.get("sop_id", ""))
            elif event.action == "step_completed":
                attempts += int(event.payload.get("attempts", 0))
                step_id = str(event.payload.get("step_id", ""))
                if step_id:
                    steps.append(step_id)
            elif event.action == "approval_requested":
                approval_id = str(event.payload.get("approval_id", "")) or None
                approval_status = "pending"
                approval_stage = int(event.payload.get("stage", 0))
            elif event.action == "run_resumed":
                approval_status = "pending"
            elif event.action == "run_completed":
                approval_status = approval_status or "approved"
            elif event.action == "run_failed":
                failure = str(event.payload.get("failure", "")) or None
        task.attempts = attempts
        task.steps = steps
        task.approval_id = approval_id
        task.approval_status = approval_status
        task.approval_stage = approval_stage
        task.failure = failure
        status, stage, stage_number = current_stage(events)
        task.status = status
        task.stage = stage
        task.stage_number = stage_number
        return task

    def _request_text(self, task_id: str) -> str:
        """The requirement of a task, from the state file of the run."""
        path = self._runs_directory / f"{task_id}.json"
        if not path.is_file():
            return ""
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return ""
        request = data.get("request", "")
        return request if isinstance(request, str) else ""

    def list_tasks(self, tenant_id: str) -> list[TaskSummary]:
        """Every task of a tenant, the newest first."""
        tasks = [
            self._task(task_id, events)
            for task_id, events in self._grouped(tenant_id).items()
        ]
        tasks.sort(key=lambda task: (task.created_at, task.task_id), reverse=True)
        return [TaskSummary(**self._summary_fields(task)) for task in tasks]

    @staticmethod
    def _summary_fields(task: _Task) -> dict[str, Any]:
        return {
            "task_id": task.task_id,
            "tenant_id": task.tenant_id,
            "sop_id": task.sop_id,
            "status": task.status,
            "stage": task.stage,
            "stage_number": task.stage_number,
            "created_at": task.created_at,
            "updated_at": task.updated_at,
            "attempts": task.attempts,
            "approval_id": task.approval_id,
            "approval_status": task.approval_status,
            "approval_stage": task.approval_stage,
            "failure": task.failure,
        }

    def get_task(self, task_id: str, tenant_id: str) -> TaskView:
        """One task of a tenant."""
        events = self._grouped(tenant_id).get(task_id)
        if not events:
            raise NotFoundError(f"unknown task '{task_id}'")
        task = self._task(task_id, events)
        return TaskView(
            **self._summary_fields(task),
            request=self._request_text(task_id),
        )

    def task_events(self, task_id: str, tenant_id: str) -> list[TaskEventView]:
        """The audit events of a task."""
        events = self._grouped(tenant_id).get(task_id)
        if not events:
            raise NotFoundError(f"unknown task '{task_id}'")
        return [
            TaskEventView(
                event_id=event.event_id,
                seq=event.seq,
                timestamp=event.timestamp,
                actor=event.actor,
                action=event.action,
                payload=event.payload,
            )
            for event in events
        ]

    # --- the approvals --------------------------------------------------

    def pending_approvals(self, tenant_id: str) -> list[ApprovalView]:
        """The approvals that wait for a decision, for one tenant."""
        tasks = self._grouped(tenant_id)
        approval_events = {
            str(event.payload.get("approval_id", "")): event
            for events in tasks.values()
            for event in events
            if event.action == "approval_requested" and event.payload.get("approval_id")
        }
        views: list[ApprovalView] = []
        for request in self._approvals.pending():
            if request.tenant_id and request.tenant_id != tenant_id:
                continue
            event = approval_events.get(request.approval_id)
            if event is not None:
                event_run_id = str(event.payload.get("run_id", ""))
                if event_run_id and (
                    request.run_id != event_run_id or request.tenant_id != tenant_id
                ):
                    request = self._approvals.reassociate(
                        request.approval_id,
                        run_id=event_run_id,
                        tenant_id=tenant_id,
                    )
            elif request.tenant_id != tenant_id:
                # Legacy files without a tenant can only be exposed through
                # their matching approval_requested event in this tenant.
                continue
            views.append(self.approval_view(request))
        return views

    def approval(self, approval_id: str, tenant_id: str) -> ApprovalRequest:
        """One approval of a tenant."""
        request = self._approvals.get(approval_id)
        if request is None or (
            request.tenant_id != tenant_id and request.run_id not in self._grouped(tenant_id)
        ):
            raise NotFoundError(f"unknown approval '{approval_id}'")
        return request

    @staticmethod
    def approval_view(request: ApprovalRequest) -> ApprovalView:
        """The view of one approval.

        The hash is the one of the artifact as it stands now: the caller
        sends it back with the decision, so a decision can never be taken on
        an artifact that changed in the meantime.
        """
        return ApprovalView(
            approval_id=request.approval_id,
            run_id=request.run_id,
            gate_id=request.gate_id,
            stage=request.stage,
            artifact_type=request.artifact_type,
            status=request.status,
            requested_at=request.requested_at,
            decided_at=request.decided_at,
            decided_by=request.decided_by,
            note=request.note,
            artifact_hash=request.artifact_hash or artifact_hash(request.artifact),
        )

    # --- the artifact ---------------------------------------------------

    def artifact(self, task_id: str, tenant_id: str) -> ArtifactView:
        """The signed manifest of a task and its verification status."""
        events = self._grouped(tenant_id).get(task_id)
        if not events:
            raise NotFoundError(f"unknown task '{task_id}'")
        signed_event: AuditEvent | None = None
        for event in events:
            if event.action == "artifact_signed":
                signed_event = event
        if signed_event is None:
            raise NotFoundError(f"the task '{task_id}' has no signed artifact yet")
        artifact_id = str(signed_event.payload.get("artifact_id", ""))
        directory = self._artifact_root / artifact_id
        try:
            signed = load_signed_manifest(directory)
        except Exception as exc:
            raise NotFoundError(f"the manifest of the artifact is missing: {exc}") from exc
        return self._verify(artifact_id, signed)

    def _verifier(self) -> Verifier | None:
        path = self._keys_directory / PUBLIC_KEY_NAME
        if not path.is_file():
            return None
        return Verifier(load_public_key(path))

    def _verify(self, artifact_id: str, signed: SignedManifest) -> ArtifactView:
        """Recompute the manifest and check the signature of the artifact."""
        checks: list[ManifestCheck] = []
        manifest = signed.manifest
        if verify_manifest(manifest):
            checks.append(
                ManifestCheck(
                    name="root_hash",
                    passed=True,
                    detail="the root hash matches the manifest body",
                )
            )
        else:
            checks.append(
                ManifestCheck(
                    name="root_hash",
                    passed=False,
                    detail="the root hash does not match the manifest body",
                )
            )
        verifier = self._verifier()
        if verifier is None:
            checks.append(
                ManifestCheck(
                    name="signature",
                    passed=False,
                    detail="the public key of the host is missing",
                )
            )
        elif verifier.verify(signature_payload(manifest.root_hash), signed.signature):
            checks.append(
                ManifestCheck(
                    name="signature",
                    passed=True,
                    detail="the signature verifies against the public key",
                )
            )
        else:
            checks.append(
                ManifestCheck(
                    name="signature",
                    passed=False,
                    detail="the signature does not verify against the public key",
                )
            )
        if self._event_log.contains_hash(manifest.log_head_hash):
            checks.append(
                ManifestCheck(
                    name="log_head",
                    passed=True,
                    detail="the audit log holds the signed head",
                )
            )
        else:
            checks.append(
                ManifestCheck(
                    name="log_head",
                    passed=False,
                    detail="the audit log does not hold the signed head",
                )
            )
        failures = [check for check in checks if not check.passed]
        return ArtifactView(
            artifact_id=artifact_id,
            manifest=manifest.model_dump(mode="json"),
            signature=signed.signature,
            verified=not failures,
            reason=failures[0].detail if failures else "the artifact matches its signed manifest",
            checks=checks,
        )

    # --- the metrics ----------------------------------------------------

    def metrics(self, tenant_id: str) -> MetricsView:
        """The counters of a tenant."""
        grouped = self._grouped(tenant_id)
        tasks = [self._task(task_id, events) for task_id, events in grouped.items()]
        completed = sum(1 for task in tasks if task.status == "completed")
        failed = sum(1 for task in tasks if task.status == "failed")
        blocked = sum(1 for task in tasks if task.status == "blocked")
        decided = completed + failed
        attempts = {task.task_id: task.attempts for task in tasks}
        findings = self._findings(tenant_id)
        return MetricsView(
            tenant_id=tenant_id,
            tasks_total=len(tasks),
            tasks_completed=completed,
            tasks_failed=failed,
            tasks_blocked=blocked,
            pass_rate=round(completed / decided, 4) if decided else 0.0,
            attempts_total=sum(attempts.values()),
            attempts_per_task=attempts,
            tokens_per_model_today=self._tokens_today(),
            security_findings=findings,
            security_details=self._security_details(tenant_id),
            risk_signals=self._risk_signals(tenant_id),
            rollout=self._rollout(tenant_id),
        )

    def _findings(self, tenant_id: str) -> list[SecurityFindingCount]:
        """The security findings of the runs of the tenant."""
        counts = dict.fromkeys(SEVERITIES, 0)
        for task_id in self._grouped(tenant_id):
            for output in self._outputs(task_id):
                for finding in output.get("security_findings", []):
                    severity = str(finding.get("severity", "medium"))
                    counts[severity] = counts.get(severity, 0) + 1
        return [
            SecurityFindingCount(severity=severity, count=counts[severity])
            for severity in SEVERITIES
            if counts[severity]
        ]

    def _outputs(self, task_id: str) -> list[dict[str, Any]]:
        """The artifacts of a run, from its state file."""
        path = self._runs_directory / f"{task_id}.json"
        if not path.is_file():
            return []
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return []
        outputs = data.get("outputs", {})
        if not isinstance(outputs, dict):
            return []
        return [value for value in outputs.values() if isinstance(value, dict)]


    def _security_details(self, tenant_id: str) -> list[SecurityFindingView]:
        """Findings from the final security-gate report of each run."""
        details: list[SecurityFindingView] = []
        for task_id in self._grouped(tenant_id):
            path = self._runs_directory / f"{task_id}.json"
            if not path.is_file():
                continue
            try:
                state = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            outputs = state.get("outputs", {})
            report = outputs.get("security_gate") if isinstance(outputs, dict) else None
            findings = report.get("security_findings", []) if isinstance(report, dict) else []
            for item in findings:
                if not isinstance(item, dict):
                    continue
                details.append(
                    SecurityFindingView(
                        run_id=task_id,
                        rule=str(item.get("rule", "unknown")),
                        severity=str(item.get("severity", "medium")),
                        file=str(item.get("file", "")),
                        line=int(item.get("line", 0) or 0),
                        message=str(item.get("message", "")),
                        tool=str(item.get("tool", "")),
                    )
                )
        return details

    def _risk_signals(self, tenant_id: str) -> int:
        """The number of risk signals the tenant raised."""
        total = 0
        for events in self._grouped(tenant_id).values():
            for event in events:
                if event.action == "risk_assessed":
                    total += len(event.payload.get("risk_signals", []))
        return total

    def _tokens_today(self) -> list[TokenUsage]:
        """The tokens every model used today."""
        if self._conversations is None:
            return []
        today = datetime.now(UTC).date().isoformat()
        totals: dict[str, int] = {}
        for record in self._conversations.read_all():
            if not record.timestamp.startswith(today):
                continue
            totals[record.model] = totals.get(record.model, 0) + record.total_tokens
        return [
            TokenUsage(model=model, total_tokens=totals[model]) for model in sorted(totals)
        ]

    def _rollout(self, tenant_id: str) -> RolloutState:
        """The state of the last rollout of the tenant."""
        state = RolloutState()
        for events in self._grouped(tenant_id).values():
            for event in events:
                payload = event.payload
                if event.action == "deployment_started":
                    state.deployment_id = str(payload.get("deployment_id", ""))
                    state.version = str(payload.get("version", ""))
                    state.slot = str(payload.get("slot", ""))
                    state.status = "starting"
                    state.error_rate_threshold = float(payload.get("error_rate_threshold", 0.0))
                    state.steps = []
                elif event.action == "traffic_measured":
                    state.steps.append(
                        {
                            "percent": payload.get("percent", 0),
                            "requests": payload.get("requests", 0),
                            "errors": payload.get("errors", 0),
                            "error_rate": payload.get("error_rate", 0.0),
                            "healthy": payload.get("healthy", True),
                        }
                    )
                elif event.action == "deployment_completed":
                    state.status = "deployed"
                elif event.action == "deployment_rolled_back":
                    state.status = "rolled_back"
                elif event.action == "deployment_refused":
                    state.status = "refused"
        return state
