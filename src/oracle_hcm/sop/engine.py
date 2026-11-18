"""SOP execution engine.

The engine is deterministic code. It resolves each step's input from the run
context, calls the named agent, validates the produced artifact against the
step's declared output schema, retries on failure and then evaluates the
step's gates. A gate that needs a human decision suspends the run, and the
run can later be resumed from the suspended step. A step may declare a loop,
which repeats the step until its condition holds or the limit is reached.
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass, field
from typing import Any, Literal, Protocol

from pydantic import BaseModel

from oracle_hcm.errors import ConfigurationError
from oracle_hcm.sop.models import GateSpec, LoopCondition, LoopSpec, SopDefinition, SopStep

__all__ = [
    "AgentCallable",
    "GateEvaluator",
    "GateOutcome",
    "GateStatus",
    "SopEngine",
    "SopResume",
    "SopRunResult",
    "StepResult",
    "resolve_template",
]

AgentCallable = Callable[[dict[str, Any]], Awaitable[BaseModel]]

GateStatus = Literal["passed", "failed", "pending_approval"]


@dataclass(frozen=True)
class GateOutcome:
    """Result of evaluating one gate."""

    status: GateStatus
    detail: str = ""
    data: dict[str, Any] = field(default_factory=dict)


class GateEvaluator(Protocol):
    """Evaluates one gate."""

    async def evaluate(self, gate: GateSpec, context: dict[str, Any]) -> GateOutcome: ...


@dataclass(frozen=True)
class StepResult:
    """Outcome of one executed step."""

    step_id: str
    agent: str
    output: BaseModel
    attempts: int


@dataclass(frozen=True)
class SopResume:
    """State of a suspended run, used to continue where it stopped."""

    index: int
    outputs: dict[str, BaseModel]
    results: list[StepResult]
    pending_result: StepResult


@dataclass
class SopRunResult:
    """Outcome of a whole SOP run."""

    sop_id: str
    status: Literal["completed", "failed", "suspended"]
    steps: list[StepResult] = field(default_factory=list)
    outputs: dict[str, BaseModel] = field(default_factory=dict)
    pending_gate: GateSpec | None = None
    pending_outcome: GateOutcome | None = None
    failure: str | None = None

    @property
    def completed(self) -> bool:
        return self.status == "completed"


def _lookup(container: Any, path: str) -> Any:
    current = container
    for part in path.split("."):
        if isinstance(current, BaseModel):
            if not hasattr(current, part):
                raise KeyError(path)
            current = getattr(current, part)
        elif isinstance(current, dict):
            if part not in current:
                raise KeyError(path)
            current = current[part]
        else:
            raise KeyError(path)
    return current


def resolve_template(
    value: Any,
    context: Mapping[str, Any],
    outputs: Mapping[str, BaseModel],
) -> Any:
    """Resolve $-prefixed references against the context and prior outputs.

    "$request" reads from the run context, "$steps.<step_id>" reads the output
    of an earlier step, optionally followed by a field path.
    """
    if isinstance(value, str):
        if not value.startswith("$"):
            return value
        path = value[1:]
        if path.startswith("steps."):
            rest = path[len("steps.") :]
            step_id, _, field_path = rest.partition(".")
            if step_id not in outputs:
                raise KeyError(f"step '{step_id}' has not produced an output yet")
            target: Any = outputs[step_id]
            if not field_path:
                return target.model_dump(mode="json") if isinstance(target, BaseModel) else target
            return _lookup(target, field_path)
        return _lookup(context, path)
    if isinstance(value, dict):
        return {key: resolve_template(item, context, outputs) for key, item in value.items()}
    if isinstance(value, list):
        return [resolve_template(item, context, outputs) for item in value]
    return value


def _compare(left: Any, op: str, right: Any) -> bool:
    if op == "eq":
        return bool(left == right)
    if op == "ne":
        return bool(left != right)
    if op == "gt":
        return bool(left > right)
    if op == "ge":
        return bool(left >= right)
    if op == "lt":
        return bool(left < right)
    if op == "le":
        return bool(left <= right)
    raise ConfigurationError(f"unsupported loop condition operator '{op}'")


class SopEngine:
    """Executes SOP definitions."""

    def __init__(
        self,
        *,
        agents: Mapping[str, AgentCallable],
        schemas: Mapping[str, type[BaseModel]],
        gates: Mapping[str, GateEvaluator],
    ) -> None:
        self._agents = dict(agents)
        self._schemas = dict(schemas)
        self._gates = dict(gates)

    def _agent_for(self, step: SopStep) -> AgentCallable:
        try:
            return self._agents[step.agent]
        except KeyError as exc:
            raise ConfigurationError(
                f"step '{step.step_id}' references unknown agent '{step.agent}'"
            ) from exc

    def _schema_for(self, step: SopStep) -> type[BaseModel]:
        try:
            return self._schemas[step.output_schema]
        except KeyError as exc:
            raise ConfigurationError(
                f"step '{step.step_id}' references unknown output schema '{step.output_schema}'"
            ) from exc

    async def _run_step(
        self,
        step: SopStep,
        context: Mapping[str, Any],
        outputs: Mapping[str, BaseModel],
    ) -> StepResult:
        agent = self._agent_for(step)
        schema = self._schema_for(step)
        payload = resolve_template(step.input, context, outputs)
        if not isinstance(payload, dict):
            payload = {"input": payload}
        last_error: Exception | None = None
        retry_payload = dict(payload)
        for attempt in range(1, step.retries + 2):
            try:
                agent_payload = dict(retry_payload)
                if step.agent == "debugger":
                    agent_payload["__engine_attempt__"] = attempt
                produced = await agent(agent_payload)
            except Exception as exc:
                last_error = exc
                validation_error = getattr(exc, "validation_error", "")
                invalid_output = getattr(exc, "invalid_output", "")
                if validation_error:
                    retry_payload = {
                        **payload,
                        "__validation_retry__": {
                            "error": str(validation_error),
                            "output": str(invalid_output)[:4000],
                        },
                    }
                continue
            if not isinstance(produced, schema):
                last_error = TypeError(
                    f"agent '{step.agent}' returned {type(produced).__name__}, "
                    f"expected {schema.__name__}"
                )
                continue
            return StepResult(
                step_id=step.step_id,
                agent=step.agent,
                output=produced,
                attempts=attempt,
            )
        raise RuntimeError(
            f"step '{step.step_id}' failed after {step.retries + 1} attempt(s): {last_error!r}"
        ) from last_error

    def _condition_met(self, condition: LoopCondition, outputs: Mapping[str, BaseModel]) -> bool:
        step_id, _, field_path = condition.path.partition(".")
        if step_id not in outputs:
            raise ConfigurationError(f"loop condition refers to unknown step '{step_id}'")
        target: Any = outputs[step_id]
        value = _lookup(target, field_path) if field_path else target
        return _compare(value, condition.op, condition.value)

    def _feedback(self, loop: LoopSpec, outputs: Mapping[str, BaseModel]) -> Any:
        if loop.feedback_step is None:
            return None
        target = outputs.get(loop.feedback_step)
        if target is None:
            return None
        return target.model_dump(mode="json") if isinstance(target, BaseModel) else target

    async def _run_looping_step(
        self,
        step: SopStep,
        context: Mapping[str, Any],
        outputs: dict[str, BaseModel],
        results: list[StepResult],
        max_phase: int,
    ) -> StepResult:
        """Run a step and repeat it while the loop condition is not met."""
        loop = step.loop
        if loop is None:
            result = await self._run_step(step, context, outputs)
            outputs[step.step_id] = result.output
            results.append(result)
            return result
        iteration = 0
        feedback: Any = None
        while True:
            iteration += 1
            loop_context = {
                **context,
                "loop": {
                    "iteration": iteration,
                    "max_iterations": loop.max_iterations,
                    "patch": feedback,
                },
            }
            result = await self._run_step(step, loop_context, outputs)
            outputs[step.step_id] = result.output
            results.append(result)
            if loop.until is not None and self._condition_met(loop.until, outputs):
                return result
            if iteration >= loop.max_iterations:
                return result
            for body_step in loop.body:
                if body_step.phase > max_phase:
                    continue
                body_result = await self._run_step(body_step, loop_context, outputs)
                outputs[body_result.step_id] = body_result.output
                results.append(body_result)
            feedback = self._feedback(loop, outputs)

    async def _evaluate_gates(
        self,
        step: SopStep,
        context: dict[str, Any],
        outputs: Mapping[str, BaseModel],
    ) -> tuple[GateSpec | None, GateOutcome | None]:
        gate_context = {**context, "outputs": dict(outputs)}
        for gate in step.gates:
            try:
                evaluator = self._gates[gate.type]
            except KeyError as exc:
                raise ConfigurationError(
                    f"step '{step.step_id}' references unknown gate type '{gate.type}'"
                ) from exc
            outcome = await evaluator.evaluate(gate, gate_context)
            if outcome.status != "passed":
                return gate, outcome
        return None, None

    async def run(
        self,
        sop: SopDefinition,
        context: Mapping[str, Any],
        *,
        max_phase: int = 3,
        resume: SopResume | None = None,
    ) -> SopRunResult:
        """Execute a SOP.

        Steps that share a parallel_group run concurrently. Steps of a later
        delivery phase are skipped.
        """
        run_context: dict[str, Any] = dict(context)
        outputs: dict[str, BaseModel] = dict(resume.outputs) if resume else {}
        results: list[StepResult] = list(resume.results) if resume else []
        pending = resume.pending_result if resume else None
        index = resume.index if resume else 0
        while index < len(sop.steps):
            step = sop.steps[index]
            if step.phase > max_phase:
                index += 1
                continue
            group = [step]
            if step.parallel_group is not None:
                while (
                    index + len(group) < len(sop.steps)
                    and sop.steps[index + len(group)].parallel_group == step.parallel_group
                ):
                    group.append(sop.steps[index + len(group)])
            try:
                recorded = False
                if pending is not None:
                    step_results = [pending]
                    pending = None
                    recorded = True
                elif len(group) == 1:
                    step_results = [
                        await self._run_looping_step(
                            group[0], run_context, outputs, results, max_phase
                        )
                    ]
                    recorded = True
                else:
                    step_results = list(
                        await asyncio.gather(
                            *(self._run_step(item, run_context, outputs) for item in group)
                        )
                    )
            except ConfigurationError:
                raise
            except Exception as exc:
                return SopRunResult(
                    sop_id=sop.sop_id,
                    status="failed",
                    steps=results,
                    outputs=outputs,
                    failure=str(exc),
                )
            if not recorded:
                for step_result in step_results:
                    outputs[step_result.step_id] = step_result.output
                    results.append(step_result)
            for member in group:
                gate, outcome = await self._evaluate_gates(member, run_context, outputs)
                if gate is not None and outcome is not None:
                    if outcome.status == "pending_approval":
                        return SopRunResult(
                            sop_id=sop.sop_id,
                            status="suspended",
                            steps=results,
                            outputs=outputs,
                            pending_gate=gate,
                            pending_outcome=outcome,
                        )
                    return SopRunResult(
                        sop_id=sop.sop_id,
                        status="failed",
                        steps=results,
                        outputs=outputs,
                        failure=outcome.detail or f"gate '{gate.gate_id}' failed",
                    )
            index += len(group)
        return SopRunResult(sop_id=sop.sop_id, status="completed", steps=results, outputs=outputs)
