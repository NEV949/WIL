"""SOP definitions.

A SOP is a YAML document describing an ordered set of steps. Each step names
the agent that runs it, the artifact it must produce, how many times it may be
retried and which gates run after it. A step may declare a loop, in which case
it is repeated until a condition holds or the iteration limit is reached.
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from oracle_hcm.schemas.artifacts import RiskTier

__all__ = ["GateSpec", "LoopCondition", "LoopSpec", "SopDefinition", "SopStep"]


class GateSpec(BaseModel):
    """A gate evaluated after a step."""

    model_config = ConfigDict(extra="forbid")

    gate_id: str
    type: str
    params: dict[str, Any] = Field(default_factory=dict)


class LoopCondition(BaseModel):
    """Condition that ends a loop.

    The path points at a field of an earlier step output, for example
    "sandbox_run.exit_code".
    """

    model_config = ConfigDict(extra="forbid")

    path: str
    op: Literal["eq", "ne", "gt", "ge", "lt", "le"] = "eq"
    value: Any = None


class LoopSpec(BaseModel):
    """Repetition of one step until a condition holds."""

    model_config = ConfigDict(extra="forbid")

    max_iterations: int = Field(default=3, ge=1, le=10)
    body: list[SopStep] = Field(default_factory=list)
    until: LoopCondition | None = None
    feedback_step: str | None = None

    @model_validator(mode="after")
    def _check_body(self) -> LoopSpec:
        for step in self.body:
            if step.parallel_group is not None:
                raise ValueError(f"loop body step '{step.step_id}' must not be parallel")
        return self


class SopStep(BaseModel):
    """One step of a SOP."""

    model_config = ConfigDict(extra="forbid")

    step_id: str
    agent: str
    input: dict[str, Any] = Field(default_factory=dict)
    output_schema: str
    retries: int = Field(default=1, ge=0)
    gates: list[GateSpec] = Field(default_factory=list)
    parallel_group: str | None = None
    loop: LoopSpec | None = None
    phase: int = Field(default=3, ge=1)

    @model_validator(mode="after")
    def _check_loop(self) -> SopStep:
        if self.loop is not None and self.parallel_group is not None:
            raise ValueError(f"step '{self.step_id}' must not be both parallel and looping")
        return self


class SopDefinition(BaseModel):
    """A complete SOP."""

    model_config = ConfigDict(extra="forbid")

    sop_id: str
    name: str
    version: str = "1.0"
    description: str = ""
    risk_tier: RiskTier = RiskTier.LOW
    steps: list[SopStep] = Field(default_factory=list)


LoopSpec.model_rebuild()
