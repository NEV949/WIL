"""The only shapes an agent is allowed to emit."""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import ClassVar, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

__all__ = [
    "AcceptanceCondition",
    "AcceptanceResult",
    "Artifact",
    "CodePatch",
    "DebugPatch",
    "DeploymentOutcome",
    "DomainEntity",
    "DomainRelationship",
    "ExecutionReport",
    "FileChange",
    "PlanStep",
    "RequirementSpec",
    "RiskTier",
    "RolloutStep",
    "SecurityFinding",
    "Severity",
    "TaskPlan",
    "TestCase",
    "TestSuite",
]

Severity = Literal["low", "medium", "high", "critical"]


def utc_now_iso() -> str:
    return datetime.now(UTC).isoformat()


class RiskTier(StrEnum):
    """Risk classification of a task.

    Classification may only be raised, never lowered, by later stages.
    """

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"

    @property
    def rank(self) -> int:
        return {"low": 0, "medium": 1, "high": 2}[self.value]

    def at_least(self, other: RiskTier) -> bool:
        return self.rank >= other.rank


class Artifact(BaseModel):
    """Common fields for every agent artifact."""

    model_config = ConfigDict(extra="forbid")

    schema_version: str = "1.0"
    created_at: str = Field(default_factory=utc_now_iso)


class DomainEntity(BaseModel):
    """One entity of the domain the requirement talks about."""

    model_config = ConfigDict(extra="forbid")

    name: str
    description: str = ""
    attributes: list[str] = Field(default_factory=list)


class DomainRelationship(BaseModel):
    """One relation between two domain entities."""

    model_config = ConfigDict(extra="forbid")

    source: str
    target: str
    kind: str = "references"
    description: str = ""


class RequirementSpec(BaseModel):
    """Normalised requirement produced by the requirements agent."""

    model_config = ConfigDict(extra="forbid")

    requirement_id: str
    title: str
    description: str
    acceptance_criteria: list[str] = Field(min_length=1)
    domain_entities: list[str] = Field(default_factory=list)
    entities: list[DomainEntity] = Field(default_factory=list)
    relationships: list[DomainRelationship] = Field(default_factory=list)
    task_type: str = "feature"
    constraints: list[str] = Field(default_factory=list)
    non_functional_requirements: list[str] = Field(default_factory=list)
    risk_keywords: list[str] = Field(default_factory=list)
    declared_permissions: list[str] = Field(default_factory=list)
    source: str | None = None

    def entity_names(self) -> list[str]:
        """Every entity of the requirement, whichever field carries it."""
        names = [entity.name for entity in self.entities]
        names.extend(name for name in self.domain_entities if name not in names)
        return names


class PlanStep(BaseModel):
    """One step of a task plan."""

    model_config = ConfigDict(extra="forbid")

    step_id: str
    description: str
    target_files: list[str] = Field(default_factory=list)
    depends_on: list[str] = Field(default_factory=list)


class TaskPlan(Artifact):
    """Ordered plan for implementing one requirement."""

    plan_id: str
    requirement_id: str
    steps: list[PlanStep] = Field(default_factory=list)


class FileChange(BaseModel):
    """A single file mutation carried by a patch."""

    model_config = ConfigDict(extra="forbid")

    path: str
    operation: Literal["create", "modify", "delete"]
    content: str = ""
    sha256: str | None = None

    @field_validator("path")
    @classmethod
    def _reject_traversal(cls, value: str) -> str:
        if ".." in value.split("/") or value.startswith("/"):
            raise ValueError(f"path must be relative and must not traverse upwards: {value}")
        return value


class CodePatch(Artifact):
    """Code produced by the coder agent."""

    patch_id: str
    requirement_id: str
    summary: str = ""
    files: list[FileChange] = Field(default_factory=list)


class TestCase(BaseModel):
    """One generated test, linked back to the requirements it covers."""

    __test__: ClassVar[bool] = False

    model_config = ConfigDict(extra="forbid")

    test_id: str
    requirement_ids: list[str] = Field(default_factory=list)
    target_module: str
    test_code: str
    kind: Literal["unit", "integration", "property"] = "unit"
    deterministic: bool = True
    seed: int | None = None


class TestSuite(Artifact):
    """Test suite produced by the test designer agent."""

    __test__: ClassVar[bool] = False

    suite_id: str
    requirement_id: str
    tests: list[TestCase] = Field(default_factory=list)

    def covered_requirement_ids(self) -> set[str]:
        covered: set[str] = set()
        for case in self.tests:
            covered.update(case.requirement_ids)
        return covered


class SecurityFinding(BaseModel):
    """One finding produced by a scanner or by a policy check."""

    model_config = ConfigDict(extra="forbid")

    rule: str
    severity: Severity = "medium"
    file: str = ""
    line: int = 0
    message: str = ""
    tool: str = ""

    @property
    def blocking(self) -> bool:
        return self.severity in ("high", "critical")


class AcceptanceCondition(BaseModel):
    """One acceptance condition and its outcome."""

    model_config = ConfigDict(extra="forbid")

    name: str
    passed: bool
    detail: str = ""


class AcceptanceResult(BaseModel):
    """Structured outcome of the acceptance gate."""

    model_config = ConfigDict(extra="forbid")

    conditions: list[AcceptanceCondition] = Field(default_factory=list)
    risk_tier: RiskTier = RiskTier.LOW
    approval_id: str | None = None

    @property
    def passed(self) -> bool:
        return all(condition.passed for condition in self.conditions)

    def failures(self) -> list[AcceptanceCondition]:
        return [condition for condition in self.conditions if not condition.passed]


class RolloutStep(BaseModel):
    """One traffic shift of a canary rollout."""

    model_config = ConfigDict(extra="forbid")

    percent: int = Field(ge=0, le=100)
    requests: int = Field(ge=0)
    errors: int = Field(ge=0)
    error_rate: float = Field(ge=0.0)
    healthy: bool = True
    detail: str = ""


class DeploymentOutcome(BaseModel):
    """The result of a deployment of a signed artifact."""

    model_config = ConfigDict(extra="forbid")

    deployment_id: str
    version: str
    status: Literal["deployed", "rolled_back", "refused"] = "deployed"
    image: str = ""
    root_hash: str = ""
    artifact_id: str = ""
    steps: list[RolloutStep] = Field(default_factory=list)
    rolled_back: bool = False
    rollback_reason: str = ""
    retired_version: str = ""
    error_rate_threshold: float = Field(ge=0.0)
    router_port: int = Field(default=0, ge=0)


class ExecutionReport(Artifact):
    """Result of running the suite inside the sandbox."""

    run_id: str
    requirement_id: str
    command: str
    exit_code: int
    stdout: str = ""
    stderr: str = ""
    tests_passed: int = 0
    tests_failed: int = 0
    tests_skipped: int = 0
    coverage_percent: float = 0.0
    duration_seconds: float = 0.0
    mypy_clean: bool = False
    mypy_output: str = ""
    coverage_diagnostic: str = ""
    security_events: list[str] = Field(default_factory=list)
    produced_files: list[str] = Field(default_factory=list)
    passed_tests: list[str] = Field(default_factory=list)
    failed_tests: list[str] = Field(default_factory=list)
    risk_tier: RiskTier = RiskTier.LOW
    risk_signals: list[str] = Field(default_factory=list)
    security_findings: list[SecurityFinding] = Field(default_factory=list)
    acceptance: AcceptanceResult | None = None
    deterministic: bool = False
    workspace_mount: str = ""
    writable_paths: list[str] = Field(default_factory=list)
    workspace_path: str = ""
    artifact_id: str = ""
    manifest_path: str = ""
    deployment: DeploymentOutcome | None = None


class DebugPatch(Artifact):
    """A repair proposed by the debugger agent."""

    patch_id: str
    requirement_id: str
    attempt: int = Field(ge=1)
    strategy: str = ""
    code_slice: str = ""
    error_excerpt: str = ""
    proposed_changes: list[FileChange] = Field(default_factory=list)
    model: str = ""
