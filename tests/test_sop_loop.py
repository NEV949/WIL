"""The SOP engine: loops, parallel steps, phases and resume."""

from __future__ import annotations

import asyncio
import time
from typing import Any

import pytest
from pydantic import BaseModel

from oracle_hcm.errors import ConfigurationError
from oracle_hcm.sop.engine import GateOutcome, SopEngine, SopResume, StepResult
from oracle_hcm.sop.models import GateSpec, LoopCondition, LoopSpec, SopDefinition, SopStep


class Counter(BaseModel):
    """A trivial artifact so the engine has something to validate."""

    value: int = 0


class PassingGate:
    async def evaluate(self, gate: GateSpec, context: dict[str, Any]) -> GateOutcome:
        return GateOutcome(status="passed")


class HoldingGate:
    async def evaluate(self, gate: GateSpec, context: dict[str, Any]) -> GateOutcome:
        return GateOutcome(status="pending_approval", data={"approval_id": "a-1"})


def _engine(
    agents: dict[str, Any], gates: dict[str, Any] | None = None
) -> SopEngine:
    return SopEngine(agents=agents, schemas={"Counter": Counter}, gates=gates or {})


def _step(
    step_id: str,
    agent: str,
    *,
    step_input: dict[str, Any] | None = None,
    retries: int = 1,
    gates: list[GateSpec] | None = None,
    parallel_group: str | None = None,
    loop: LoopSpec | None = None,
    phase: int = 3,
) -> SopStep:
    return SopStep(
        step_id=step_id,
        agent=agent,
        input=step_input or {},
        output_schema="Counter",
        retries=retries,
        gates=gates or [],
        parallel_group=parallel_group,
        loop=loop,
        phase=phase,
    )


def _sop(*steps: SopStep) -> SopDefinition:
    return SopDefinition(sop_id="test", name="test", steps=list(steps))


async def test_a_plain_step_produces_its_output() -> None:
    async def agent(payload: dict[str, Any]) -> Counter:
        return Counter(value=1)

    engine = _engine({"one": agent})
    result = await engine.run(_sop(_step("a", "one")), {})

    assert result.status == "completed"
    output = result.outputs["a"]
    assert isinstance(output, Counter)
    assert output.value == 1


async def test_a_failing_agent_fails_the_run() -> None:
    async def agent(payload: dict[str, Any]) -> Counter:
        raise RuntimeError("no")

    engine = _engine({"one": agent})
    result = await engine.run(_sop(_step("a", "one", retries=1)), {})

    assert result.status == "failed"
    assert "no" in (result.failure or "")


async def test_an_unknown_agent_is_a_configuration_error() -> None:
    engine = _engine({})
    with pytest.raises(ConfigurationError):
        await engine.run(_sop(_step("a", "missing")), {})


async def test_parallel_steps_overlap() -> None:
    async def slow(payload: dict[str, Any]) -> Counter:
        await asyncio.sleep(0.2)
        return Counter(value=1)

    engine = _engine({"slow": slow})
    sop = _sop(
        _step("a", "slow", parallel_group="impl"),
        _step("b", "slow", parallel_group="impl"),
    )

    started = time.monotonic()
    result = await engine.run(sop, {})
    elapsed = time.monotonic() - started

    assert result.status == "completed"
    assert elapsed < 0.35
    assert set(result.outputs) == {"a", "b"}


async def test_a_loop_repeats_until_the_condition_holds() -> None:
    calls: list[int] = []

    async def agent(payload: dict[str, Any]) -> Counter:
        calls.append(1)
        return Counter(value=len(calls))

    step = _step(
        "a",
        "one",
        loop=LoopSpec(
            max_iterations=5,
            until=LoopCondition(path="a.value", op="ge", value=3),
        ),
    )
    engine = _engine({"one": agent})

    result = await engine.run(_sop(step), {})

    assert len(calls) == 3
    output = result.outputs["a"]
    assert isinstance(output, Counter)
    assert output.value == 3


async def test_a_loop_stops_at_the_iteration_limit() -> None:
    calls: list[int] = []

    async def agent(payload: dict[str, Any]) -> Counter:
        calls.append(1)
        return Counter(value=0)

    step = _step(
        "a",
        "one",
        loop=LoopSpec(
            max_iterations=3,
            until=LoopCondition(path="a.value", op="eq", value=99),
        ),
    )
    engine = _engine({"one": agent})

    await engine.run(_sop(step), {})

    assert len(calls) == 3


async def test_the_loop_body_runs_between_the_iterations() -> None:
    calls: list[str] = []

    async def agent(payload: dict[str, Any]) -> Counter:
        calls.append("main")
        return Counter(value=0)

    async def repair(payload: dict[str, Any]) -> Counter:
        calls.append("repair")
        return Counter(value=0)

    step = _step(
        "a",
        "one",
        loop=LoopSpec(
            max_iterations=3,
            until=LoopCondition(path="a.value", op="eq", value=99),
            feedback_step="fix",
            body=[_step("fix", "repair")],
        ),
    )
    engine = _engine({"one": agent, "repair": repair})

    await engine.run(_sop(step), {})

    assert calls == ["main", "repair", "main", "repair", "main"]


async def test_the_repair_is_handed_to_the_next_iteration() -> None:
    seen: list[dict[str, Any]] = []
    body: list[dict[str, Any]] = []

    async def agent(payload: dict[str, Any]) -> Counter:
        seen.append(payload)
        return Counter(value=0)

    async def repair(payload: dict[str, Any]) -> Counter:
        body.append(payload)
        return Counter(value=0)

    step = _step(
        "a",
        "one",
        step_input={"patch": "$loop.patch", "iteration": "$loop.iteration"},
        loop=LoopSpec(
            max_iterations=3,
            until=LoopCondition(path="a.value", op="eq", value=99),
            feedback_step="fix",
            body=[_step("fix", "repair")],
        ),
    )
    engine = _engine({"one": agent, "repair": repair})

    await engine.run(_sop(step), {})

    assert seen[0]["patch"] is None
    assert seen[0]["iteration"] == 1
    assert seen[1]["patch"] == {"value": 0}
    assert seen[1]["iteration"] == 2
    assert len(body) == 2


async def test_a_step_of_a_later_phase_is_skipped() -> None:
    async def agent(payload: dict[str, Any]) -> Counter:
        return Counter(value=1)

    engine = _engine({"one": agent})
    sop = _sop(_step("a", "one", phase=3), _step("b", "one", phase=4))

    result = await engine.run(sop, {}, max_phase=3)

    assert result.status == "completed"
    assert "b" not in result.outputs


async def test_a_pending_gate_suspends_the_run() -> None:
    async def agent(payload: dict[str, Any]) -> Counter:
        return Counter(value=1)

    step = _step("a", "one", gates=[GateSpec(gate_id="g", type="hold", params={})])
    engine = _engine({"one": agent}, {"hold": HoldingGate()})

    result = await engine.run(_sop(step), {})

    assert result.status == "suspended"
    assert result.pending_gate is not None
    assert result.pending_outcome is not None


async def test_a_resumed_run_continues_at_the_suspended_step() -> None:
    calls: list[str] = []

    async def agent(payload: dict[str, Any]) -> Counter:
        calls.append("a")
        return Counter(value=1)

    async def other(payload: dict[str, Any]) -> Counter:
        calls.append("b")
        return Counter(value=2)

    step = _step("a", "one", gates=[GateSpec(gate_id="g", type="hold", params={})])
    sop = _sop(step, _step("b", "other"))
    engine = _engine({"one": agent, "other": other}, {"hold": PassingGate()})

    resume = SopResume(
        index=0,
        outputs={"a": Counter(value=1)},
        results=[StepResult(step_id="a", agent="one", output=Counter(value=1), attempts=1)],
        pending_result=StepResult(
            step_id="a", agent="one", output=Counter(value=1), attempts=1
        ),
    )

    result = await engine.run(sop, {}, resume=resume)

    assert result.status == "completed"
    assert calls == ["b"]
    output = result.outputs["b"]
    assert isinstance(output, Counter)
    assert output.value == 2


def test_a_step_cannot_be_parallel_and_looping() -> None:
    with pytest.raises(ValueError):
        _step("a", "one", parallel_group="g", loop=LoopSpec(max_iterations=2))


def test_a_loop_body_step_cannot_be_parallel() -> None:
    with pytest.raises(ValueError):
        LoopSpec(max_iterations=2, body=[_step("fix", "one", parallel_group="g")])
