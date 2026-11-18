"""The shapes the gateway accepts and returns.

Every request is validated by a Pydantic model with a maximum length on each
field, so an oversized or malformed request never reaches the orchestrator.
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

__all__ = [
    "ApprovalDecisionRequest",
    "ApprovalView",
    "ArtifactView",
    "ErrorResponse",
    "LoginRequest",
    "LoginResponse",
    "LogoutResponse",
    "ManifestCheck",
    "MetricsView",
    "RolloutState",
    "SecurityFindingCount",
    "TaskCreateRequest",
    "TaskCreatedResponse",
    "TaskEventView",
    "TaskSummary",
    "TaskView",
    "TokenUsage",
]


class ErrorResponse(BaseModel):
    """The body of every error."""

    error: str
    message: str


class LoginRequest(BaseModel):
    """The credentials of a login."""

    model_config = ConfigDict(extra="forbid")

    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=256)


class LoginResponse(BaseModel):
    """What a successful login returns."""

    user_id: str
    role: str
    tenant_id: str
    csrf_token: str
    expires_at: str


class LogoutResponse(BaseModel):
    """What a logout returns."""

    user_id: str
    logged_out: bool = True


class TaskCreateRequest(BaseModel):
    """The requirement of a new task."""

    model_config = ConfigDict(extra="forbid")

    request: str = Field(min_length=1, max_length=20_000)
    sop_id: str = Field(default="sop_lightweight", min_length=1, max_length=64)


class TaskCreatedResponse(BaseModel):
    """The answer to a submitted task."""

    task_id: str
    tenant_id: str
    status: str
    stage: str


class TaskSummary(BaseModel):
    """One task of the list."""

    task_id: str
    tenant_id: str
    sop_id: str = ""
    status: str
    stage: str
    stage_number: int = 0
    created_at: str = ""
    updated_at: str = ""
    attempts: int = 0
    approval_id: str | None = None
    approval_status: str | None = None
    approval_stage: int | None = None
    failure: str | None = None


class TaskView(TaskSummary):
    """One task with its requirement."""

    request: str = ""


class TaskEventView(BaseModel):
    """One audit event of a task."""

    event_id: str
    seq: int
    timestamp: str
    actor: str
    action: str
    payload: dict[str, Any] = Field(default_factory=dict)


class ApprovalView(BaseModel):
    """One approval request."""

    approval_id: str
    run_id: str
    gate_id: str
    stage: int
    artifact_type: str
    status: str
    requested_at: str
    decided_at: str | None = None
    decided_by: str | None = None
    note: str = ""
    artifact_hash: str = ""


class ApprovalDecisionRequest(BaseModel):
    """The decision of an administrator."""

    model_config = ConfigDict(extra="forbid")

    decision: Literal["approved", "rejected"]
    comment: str = Field(default="", max_length=2000)
    artifact_hash: str = Field(min_length=64, max_length=64, pattern=r"^[0-9a-f]{64}$")


class ManifestCheck(BaseModel):
    """One check of the verification of an artifact."""

    name: str
    passed: bool
    detail: str = ""


class ArtifactView(BaseModel):
    """The signed manifest of a task and its verification status."""

    artifact_id: str
    manifest: dict[str, Any] = Field(default_factory=dict)
    signature: str = ""
    verified: bool = False
    reason: str = ""
    checks: list[ManifestCheck] = Field(default_factory=list)


class TokenUsage(BaseModel):
    """The tokens of one model today."""

    model: str
    total_tokens: int = 0


class SecurityFindingCount(BaseModel):
    """The security findings of one severity."""

    severity: str
    count: int = 0


class SecurityFindingView(BaseModel):
    """A security finding attached to a task run."""

    run_id: str
    rule: str
    severity: str
    file: str = ""
    line: int = 0
    message: str = ""
    tool: str = ""


class RolloutState(BaseModel):
    """The state of the last rollout of the tenant."""

    deployment_id: str = ""
    version: str = ""
    slot: str = ""
    status: str = "none"
    error_rate_threshold: float = 0.0
    steps: list[dict[str, Any]] = Field(default_factory=list)


class MetricsView(BaseModel):
    """The counters of the tenant."""

    tenant_id: str
    tasks_total: int = 0
    tasks_completed: int = 0
    tasks_failed: int = 0
    tasks_blocked: int = 0
    pass_rate: float = 0.0
    attempts_total: int = 0
    attempts_per_task: dict[str, int] = Field(default_factory=dict)
    tokens_per_model_today: list[TokenUsage] = Field(default_factory=list)
    security_findings: list[SecurityFindingCount] = Field(default_factory=list)
    security_details: list[SecurityFindingView] = Field(default_factory=list)
    risk_signals: int = 0
    rollout: RolloutState = Field(default_factory=RolloutState)
