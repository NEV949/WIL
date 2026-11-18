"""Tests for SOP loading and execution."""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

import pytest
from pydantic import BaseModel

from oracle_hcm.errors import ConfigurationError
from oracle_hcm.schemas.artifacts import (
    CodePatch,
    DebugPatch,
    ExecutionReport,
    RequirementSpec,
    TaskPlan,
    TestSuite,
)
from oracle_hcm.sop.engine import (
    GateOutcome,
    GateStatus,
    SopEngine,
    resolve_template,
)
from oracle_hcm.sop.loader import load_sop, load_sops
from oracle_hcm.sop.models import GateSpec, SopDefinition, SopStep

ARTIFACT_SCHEMAS: dict[str, type[BaseModel]] = {
    "RequirementSpec": RequirementSpec,
    "TaskPlan": TaskPlan,
    "CodePatch": CodePatch,
    "TestSuite": TestSuite,
    "ExecutionReport": ExecutionReport,
    "DebugPatch": DebugPatch,
}

KNOWN_AGENTS = {
    "requirements",
    "planner",
    "coder",
    "test_designer",
    "sandbox_runner",
    "debugger",
    "security_gate",
    "security_repair",
    "acceptance_gate",
    "signer",
    "deployer",
}


def _spec() -> RequirementSpec:
    return RequirementSpec(
        requirement_id="REQ-1",
        title="Employee lookup",
        description="Look up an employee by id",
        acceptance_criteria=["returns the employee record"],
    )


def _plan() -> TaskPlan:
    return TaskPlan(plan_id="PLAN-1", requirement_id="REQ-1")


def _patch() -> CodePatch:
    return CodePatch(patch_id="PATCH-1", requirement_id="REQ-1")


def _suite() -> TestSuite:
    return TestSuite(suite_id="SUITE-1", requirement_id="REQ-1")


def _report() -> ExecutionReport:
    return ExecutionReport(
        run_id="RUN-1",
        requirement_id="REQ-1",
        command="pytest",
        exit_code=0,
    )


class _ScriptedGate:
    """Gate evaluator with a fixed answer."""

    def __init__(self, status: GateStatus, detail: str = "") -> None:
        self._status = status
        self._detail = detail
        self.seen: list[GateSpec] = []

    async def evaluate(self, gate: GateSpec, context: dict[str, Any]) -> GateOutcome:
        self.seen.append(gate)
        return GateOutcome(status=self._status, detail=self._detail)


def _step(
    step_id: str,
    *,
    agent: str = "requirements",
    schema: str = "RequirementSpec",
    retries: int = 0,
    gates: list[GateSpec] | None = None,
    parallel_group: str | None = None,
    input_map: dict[str, Any] | None = None,
) -> SopStep:
    return SopStep(
        step_id=step_id,
        agent=agent,
        input=input_map or {},
        output_schema=schema,
        retries=retries,
        gates=gates or [],
        parallel_group=parallel_group,
    )


def _sop(*steps: SopStep, sop_id: str = "sop_test") -> SopDefinition:
    return SopDefinition(sop_id=sop_id, name="Test SOP", steps=list(steps))


class TestLoader:
    def test_loads_shipped_sops(self) -> None:
        definitions = load_sops()
        assert set(definitions) == {
            "sop_lightweight",
            "sop_modify_repo",
            "sop_full_module",
        }

    def test_shipped_sops_use_only_known_agents_and_schemas(self) -> None:
        for definition in load_sops().values():
            for step in definition.steps:
                assert step.agent in KNOWN_AGENTS, f"{definition.sop_id}/{step.step_id}"
                assert step.output_schema in ARTIFACT_SCHEMAS, f"{definition.sop_id}/{step.step_id}"

    def test_shipped_sops_declare_both_admin_approvals(self) -> None:
        for definition in load_sops().values():
            gates = [gate for step in definition.steps for gate in step.gates]
            approvals = [gate for gate in gates if gate.type == "admin_approval"]
            stages = sorted(gate.params.get("stage", 0) for gate in approvals)
            assert stages == [1, 2], f"{definition.sop_id} approvals: {stages}"

    def test_shipped_sops_design_tests_after_code_is_available(self) -> None:
        for definition in load_sops().values():
            step_ids = [step.step_id for step in definition.steps]
            assert step_ids.index("code") < step_ids.index("tests"), definition.sop_id
            tests = next(step for step in definition.steps if step.step_id == "tests")
            assert tests.input.get("code") == "$steps.code", definition.sop_id
            assert tests.parallel_group is None, definition.sop_id

    def test_missing_file(self, tmp_path: Path) -> None:
        with pytest.raises(ConfigurationError):
            load_sop(tmp_path / "nope.yaml")

    def test_non_mapping_document(self, tmp_path: Path) -> None:
        path = tmp_path / "bad.yaml"
        path.write_text("- a\n- b\n", encoding="utf-8")
        with pytest.raises(ConfigurationError):
            load_sop(path)

    def test_invalid_schema(self, tmp_path: Path) -> None:
        path = tmp_path / "bad.yaml"
        path.write_text("sop_id: x\nname: y\nsteps:\n  - unknown: 1\n", encoding="utf-8")
        with pytest.raises(ConfigurationError):
            load_sop(path)

    def test_missing_directory(self, tmp_path: Path) -> None:
        with pytest.raises(ConfigurationError):
            load_sops(tmp_path / "absent")

    def test_empty_directory(self, tmp_path: Path) -> None:
        with pytest.raises(ConfigurationError):
            load_sops(tmp_path)


class TestResolveTemplate:
    def test_reads_request(self) -> None:
        assert resolve_template("$request", {"request": {"a": 1}}, {}) == {"a": 1}

    def test_reads_whole_step_output(self) -> None:
        outputs = {"requirements": _spec()}
        resolved = resolve_template("$steps.requirements", {}, outputs)
        assert isinstance(resolved, dict)
        assert resolved["requirement_id"] == "REQ-1"

    def test_reads_field_of_step_output(self) -> None:
        outputs = {"requirements": _spec()}
        assert resolve_template("$steps.requirements.title", {}, outputs) == "Employee lookup"

    def test_resolves_nested_structures(self) -> None:
        outputs = {"plan": _plan()}
        value = {"a": ["$steps.plan.plan_id"], "b": {"c": "$request.title"}}
        resolved = resolve_template(value, {"request": {"title": "t"}}, outputs)
        assert resolved == {"a": ["PLAN-1"], "b": {"c": "t"}}

    def test_unknown_step_raises(self) -> None:
        with pytest.raises(KeyError):
            resolve_template("$steps.missing", {}, {})

    def test_unknown_field_raises(self) -> None:
        with pytest.raises(KeyError):
            resolve_template("$steps.requirements.nope", {}, {"requirements": _spec()})

    def test_plain_values_pass_through(self) -> None:
        assert resolve_template(7, {}, {}) == 7
        assert resolve_template("plain", {}, {}) == "plain"


class TestEngine:
    async def test_completed_run(self) -> None:
        async def agent(payload: dict[str, Any]) -> BaseModel:
            return _spec()

        engine = SopEngine(
            agents={"requirements": agent},
            schemas=ARTIFACT_SCHEMAS,
            gates={},
        )
        result = await engine.run(_sop(_step("requirements")), {"request": {"title": "x"}})
        assert result.status == "completed"
        assert result.completed
        assert [s.step_id for s in result.steps] == ["requirements"]
        assert isinstance(result.outputs["requirements"], RequirementSpec)
        assert result.failure is None
        assert result.pending_gate is None

    async def test_step_input_is_resolved(self) -> None:
        seen: dict[str, Any] = {}

        async def agent(payload: dict[str, Any]) -> BaseModel:
            seen.update(payload)
            return _spec()

        engine = SopEngine(
            agents={"requirements": agent},
            schemas=ARTIFACT_SCHEMAS,
            gates={},
        )
        await engine.run(
            _sop(_step("requirements", input_map={"request": "$request"})),
            {"request": {"title": "x"}},
        )
        assert seen == {"request": {"title": "x"}}

    async def test_agent_failure_is_retried_then_reported(self) -> None:
        calls = 0

        async def agent(payload: dict[str, Any]) -> BaseModel:
            nonlocal calls
            calls += 1
            raise RuntimeError("boom")

        engine = SopEngine(
            agents={"requirements": agent},
            schemas=ARTIFACT_SCHEMAS,
            gates={},
        )
        result = await engine.run(_sop(_step("requirements", retries=2)), {})
        assert result.status == "failed"
        assert calls == 3
        assert "boom" in (result.failure or "")

    async def test_retry_succeeds_after_transient_failure(self) -> None:
        calls = 0

        async def agent(payload: dict[str, Any]) -> BaseModel:
            nonlocal calls
            calls += 1
            if calls < 3:
                raise RuntimeError("transient")
            return _spec()

        engine = SopEngine(
            agents={"requirements": agent},
            schemas=ARTIFACT_SCHEMAS,
            gates={},
        )
        result = await engine.run(_sop(_step("requirements", retries=2)), {})
        assert result.status == "completed"
        assert result.steps[0].attempts == 3

    async def test_wrong_output_schema_fails_the_run(self) -> None:
        async def agent(payload: dict[str, Any]) -> BaseModel:
            return _plan()

        engine = SopEngine(
            agents={"requirements": agent},
            schemas=ARTIFACT_SCHEMAS,
            gates={},
        )
        result = await engine.run(_sop(_step("requirements")), {})
        assert result.status == "failed"
        assert "RequirementSpec" in (result.failure or "")

    async def test_unknown_agent_is_a_configuration_error(self) -> None:
        async def agent(payload: dict[str, Any]) -> BaseModel:
            return _spec()

        engine = SopEngine(
            agents={"requirements": agent},
            schemas=ARTIFACT_SCHEMAS,
            gates={},
        )
        with pytest.raises(ConfigurationError):
            await engine.run(_sop(_step("requirements", agent="ghost")), {})

    async def test_unknown_schema_is_a_configuration_error(self) -> None:
        async def agent(payload: dict[str, Any]) -> BaseModel:
            return _spec()

        engine = SopEngine(
            agents={"requirements": agent},
            schemas=ARTIFACT_SCHEMAS,
            gates={},
        )
        with pytest.raises(ConfigurationError):
            await engine.run(_sop(_step("requirements", schema="Ghost")), {})

    async def test_unknown_gate_type_is_a_configuration_error(self) -> None:
        async def agent(payload: dict[str, Any]) -> BaseModel:
            return _spec()

        engine = SopEngine(
            agents={"requirements": agent},
            schemas=ARTIFACT_SCHEMAS,
            gates={},
        )
        step = _step(
            "requirements",
            gates=[GateSpec(gate_id="g", type="ghost_gate")],
        )
        with pytest.raises(ConfigurationError):
            await engine.run(_sop(step), {})

    async def test_pending_approval_suspends_the_run(self) -> None:
        async def agent(payload: dict[str, Any]) -> BaseModel:
            return _spec()

        gate = _ScriptedGate("pending_approval", "waiting for an admin")
        engine = SopEngine(
            agents={"requirements": agent},
            schemas=ARTIFACT_SCHEMAS,
            gates={"admin_approval": gate},
        )
        step = _step(
            "requirements",
            gates=[GateSpec(gate_id="approval_spec", type="admin_approval")],
        )
        result = await engine.run(_sop(step, _step("plan", agent="planner")), {})
        assert result.status == "suspended"
        assert result.pending_gate is not None
        assert result.pending_gate.gate_id == "approval_spec"
        assert [s.step_id for s in result.steps] == ["requirements"]

    async def test_failed_gate_fails_the_run(self) -> None:
        async def agent(payload: dict[str, Any]) -> BaseModel:
            return _spec()

        gate = _ScriptedGate("failed", "policy violation")
        engine = SopEngine(
            agents={"requirements": agent},
            schemas=ARTIFACT_SCHEMAS,
            gates={"admin_approval": gate},
        )
        step = _step(
            "requirements",
            gates=[GateSpec(gate_id="approval_spec", type="admin_approval")],
        )
        result = await engine.run(_sop(step), {})
        assert result.status == "failed"
        assert result.failure == "policy violation"
        assert result.pending_gate is None

    async def test_parallel_group_runs_concurrently(self) -> None:
        both_started = asyncio.Event()
        started = 0

        async def coder(payload: dict[str, Any]) -> BaseModel:
            nonlocal started
            started += 1
            if started == 2:
                both_started.set()
            await asyncio.wait_for(both_started.wait(), timeout=5)
            return _patch()

        async def test_designer(payload: dict[str, Any]) -> BaseModel:
            nonlocal started
            started += 1
            if started == 2:
                both_started.set()
            await asyncio.wait_for(both_started.wait(), timeout=5)
            return _suite()

        engine = SopEngine(
            agents={"coder": coder, "test_designer": test_designer},
            schemas=ARTIFACT_SCHEMAS,
            gates={},
        )
        result = await engine.run(
            _sop(
                _step("code", agent="coder", schema="CodePatch", parallel_group="implementation"),
                _step(
                    "tests",
                    agent="test_designer",
                    schema="TestSuite",
                    parallel_group="implementation",
                ),
            ),
            {},
        )
        assert result.status == "completed"
        assert set(result.outputs) == {"code", "tests"}

    async def test_gate_on_second_parallel_member_suspends(self) -> None:
        async def coder(payload: dict[str, Any]) -> BaseModel:
            return _patch()

        async def test_designer(payload: dict[str, Any]) -> BaseModel:
            return _suite()

        gate = _ScriptedGate("pending_approval")
        engine = SopEngine(
            agents={"coder": coder, "test_designer": test_designer},
            schemas=ARTIFACT_SCHEMAS,
            gates={"admin_approval": gate},
        )
        result = await engine.run(
            _sop(
                _step("code", agent="coder", schema="CodePatch", parallel_group="implementation"),
                _step(
                    "tests",
                    agent="test_designer",
                    schema="TestSuite",
                    parallel_group="implementation",
                    gates=[GateSpec(gate_id="approval_tests", type="admin_approval")],
                ),
            ),
            {},
        )
        assert result.status == "suspended"
        assert result.pending_gate is not None
        assert result.pending_gate.gate_id == "approval_tests"
        assert set(result.outputs) == {"code", "tests"}

    async def test_sequential_steps_can_read_prior_outputs(self) -> None:
        async def requirements_agent(payload: dict[str, Any]) -> BaseModel:
            return _spec()

        async def planner(payload: dict[str, Any]) -> BaseModel:
            assert payload["spec"]["requirement_id"] == "REQ-1"
            return _plan()

        engine = SopEngine(
            agents={"requirements": requirements_agent, "planner": planner},
            schemas=ARTIFACT_SCHEMAS,
            gates={},
        )
        result = await engine.run(
            _sop(
                _step("requirements"),
                _step(
                    "plan",
                    agent="planner",
                    schema="TaskPlan",
                    input_map={"spec": "$steps.requirements"},
                ),
            ),
            {},
        )
        assert result.status == "completed"
        assert isinstance(result.outputs["plan"], TaskPlan)

    async def test_debug_patch_schema_is_accepted(self) -> None:
        async def agent(payload: dict[str, Any]) -> BaseModel:
            return DebugPatch(patch_id="D1", requirement_id="REQ-1", attempt=1)

        engine = SopEngine(
            agents={"debugger": agent},
            schemas=ARTIFACT_SCHEMAS,
            gates={},
        )
        result = await engine.run(_sop(_step("debug", agent="debugger", schema="DebugPatch")), {})
        assert result.status == "completed"
