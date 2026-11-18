"""The fake backend and the four artifact producing agents."""

from __future__ import annotations

import json
from typing import Any

import pytest
from pydantic import ValidationError

from oracle_hcm.agents.base import AgentError, _example_from_schema, extract_json_object
from oracle_hcm.agents.coder import CoderAgent
from oracle_hcm.agents.debugger import DebuggerAgent
from oracle_hcm.agents.requirements import RequirementsAgent
from oracle_hcm.agents.test_designer import TestDesignerAgent
from oracle_hcm.config.settings import Settings
from oracle_hcm.llm.fake import FakeBackend, fake_registry, fake_settings
from oracle_hcm.llm.router import LLMRouter, RawCompletion
from oracle_hcm.log.conversation import ConversationStore
from oracle_hcm.schemas.artifacts import CodePatch, DebugPatch, RequirementSpec, TestCase, TestSuite
from oracle_hcm.sop.engine import SopEngine
from oracle_hcm.sop.models import SopStep


@pytest.fixture
def router() -> LLMRouter:
    settings = fake_settings(Settings.from_env({}))
    return LLMRouter(registry=fake_registry(), settings=settings, backend=FakeBackend())


def test_fake_backend_never_needs_a_network() -> None:
    backend = FakeBackend()
    completion = backend(
        model="fake/coder",
        messages=[{"role": "user", "content": "hello"}],
        api_key="not-used-by-fake-backend",
        temperature=0.0,
        max_tokens=None,
    )
    assert json.loads(completion.text)["patch_id"] == "PATCH-1"
    assert len(backend.calls) == 1


def test_fake_backend_rejects_an_unknown_model() -> None:
    with pytest.raises(KeyError):
        FakeBackend().payload_for("fake/unknown")


def test_fake_registry_points_every_role_at_the_fake_provider() -> None:
    registry = fake_registry()
    for role in registry.roles:
        assert registry.require_configured(role).model.startswith("fake/")


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ('{"a": 1}', {"a": 1}),
        ('```json\n{"a": 1}\n```', {"a": 1}),
        ('Here you go:\n{"a": 1}\nDone.', {"a": 1}),
        ('{"a": {"b": 2}}', {"a": {"b": 2}}),
    ],
)
def test_extract_json_object_accepts_the_usual_shapes(text: str, expected: dict[str, Any]) -> None:
    assert extract_json_object(text) == expected


def test_extract_json_object_rejects_prose() -> None:
    with pytest.raises(AgentError):
        extract_json_object("there is no json here")


async def test_requirements_agent_produces_a_specification(router: LLMRouter) -> None:
    spec = await RequirementsAgent(router)({"request": "Add overtime pay"})
    assert isinstance(spec, RequirementSpec)
    assert spec.acceptance_criteria
    assert "payroll" in spec.risk_keywords


async def test_coder_agent_produces_a_patch(router: LLMRouter) -> None:
    patch = await CoderAgent(router)({"spec": {"requirement_id": "REQ-1"}})
    assert isinstance(patch, CodePatch)
    assert patch.files
    assert patch.files[0].path == "pkg/overtime.py"


async def test_test_designer_agent_produces_a_suite(router: LLMRouter) -> None:
    suite = await TestDesignerAgent(router)(
        {
            "spec": {"requirement_id": "REQ-1"},
            "code": {
                "files": [
                    {
                        "path": "src/services/punch_validation.py",
                        "content": "def validate_punch(request: PunchRequest) -> Result: ...",
                    }
                ]
            },
        }
    )
    assert isinstance(suite, TestSuite)
    assert suite.tests
    assert suite.tests[0].requirement_ids == ["REQ-1"]


def test_test_designer_prompt_uses_the_supplied_implementation(router: LLMRouter) -> None:
    prompt = TestDesignerAgent(router).build_prompt(
        {
            "spec": {"requirement_id": "REQ-1", "title": "Validate punch"},
            "code": {
                "files": [
                    {
                        "path": "src/services/punch_validation.py",
                        "content": "def validate_punch(request: PunchRequest) -> Result: ...",
                    }
                ]
            },
        }
    )

    assert "src/services/punch_validation.py" in prompt
    assert "def validate_punch(request: PunchRequest) -> Result" in prompt
    assert "Do not invent a module or API" in TestDesignerAgent.system_prompt


def test_quality_feedback_is_included_in_repair_agent_prompts(router: LLMRouter) -> None:
    feedback = {
        "mypy": 'microservice.py:33: error: Missing type arguments for generic type "dict"',
        "coverage": "No data was collected; import target was not exercised",
    }
    coder_prompt = CoderAgent(router).build_prompt(
        {"spec": {}, "quality_feedback": feedback, "current_code": {"microservice.py": "..."}}
    )
    designer_prompt = TestDesignerAgent(router).build_prompt(
        {
            "spec": {},
            "code": {"microservice.py": "..."},
            "quality_feedback": feedback,
        }
    )

    assert "Missing type arguments" in coder_prompt
    assert "mypy --strict" in CoderAgent.system_prompt
    assert "parameterize all generic types" in CoderAgent.system_prompt
    assert "No data was collected" in designer_prompt
    assert "Do not reduce the coverage threshold" in designer_prompt


async def test_debugger_agent_produces_a_repair(router: LLMRouter) -> None:
    repair = await DebuggerAgent(router)({"report": {"exit_code": 1}, "code": {}})
    assert isinstance(repair, DebugPatch)
    assert repair.attempt >= 1
    assert repair.proposed_changes


async def test_agent_rejects_an_answer_that_is_not_the_schema() -> None:
    class BrokenBackend:
        def __call__(self, **kwargs: Any) -> RawCompletion:
            return RawCompletion(text=json.dumps({"requirement_id": "REQ-1"}))

    settings = fake_settings(Settings.from_env({}))
    router = LLMRouter(
        registry=fake_registry(), settings=settings, backend=BrokenBackend()
    )
    with pytest.raises(AgentError):
        await RequirementsAgent(router)({"request": "anything"})


async def test_agent_prompt_carries_the_request(router: LLMRouter) -> None:
    agent = RequirementsAgent(router)
    prompt = agent.build_prompt({"request": "Add overtime pay"})
    assert "Add overtime pay" in prompt


async def test_test_designer_retries_invalid_kind_with_schema_feedback(tmp_path: Any) -> None:
    invalid: dict[str, Any] = {
        "suite_id": "SUITE-1",
        "requirement_id": "REQ-1",
        "tests": [
            {
                "test_id": "T-1",
                "requirement_ids": ["REQ-1"],
                "target_module": "service",
                "test_code": "def test_large_scale(): pass",
                "kind": "performance",
                "deterministic": True,
                "seed": 1,
            }
        ],
    }
    valid = {**invalid, "tests": [{**invalid["tests"][0], "kind": "property"}]}

    class ScriptedBackend:
        def __init__(self) -> None:
            self.calls: list[dict[str, Any]] = []
            self.outputs = [json.dumps(invalid), json.dumps(valid)]

        def __call__(self, **kwargs: Any) -> RawCompletion:
            self.calls.append(kwargs)
            return RawCompletion(text=self.outputs.pop(0))

    backend = ScriptedBackend()
    store = ConversationStore(tmp_path / "conversation")
    active_router = LLMRouter(
        registry=fake_registry(),
        settings=fake_settings(Settings.from_env({})),
        backend=backend,
        conversation_store=store,
    )
    agent = TestDesignerAgent(active_router)
    engine = SopEngine(
        agents={"test_designer": agent},
        schemas={"suite": TestSuite},
        gates={},
    )
    step = SopStep(
        step_id="tests",
        agent="test_designer",
        input={"spec": {"requirement_id": "REQ-1"}},
        output_schema="suite",
        retries=1,
    )

    result = await engine._run_step(step, {}, {})

    assert isinstance(result.output, TestSuite)
    assert result.output.tests[0].kind == "property"
    assert result.attempts == 2
    second_prompt = backend.calls[1]["messages"][1]["content"]
    assert "Input should be 'unit', 'integration' or 'property'" in second_prompt
    assert json.dumps(invalid) in second_prompt
    assert 'kind: ["unit", "integration", "property"]' in backend.calls[0]["messages"][0]["content"]
    with pytest.raises(ValidationError):
        TestCase.model_validate(invalid["tests"][0])

    failures = [
        record for record in store.read_all() if record.metadata.get("error_type")
    ]
    assert len(failures) == 1
    assert failures[0].metadata["error_type"] == "ValidationError"
    assert failures[0].metadata["error"]
    assert failures[0].model == "fake/test-designer"
    assert failures[0].latency_ms >= 0
    assert failures[0].attempt == 1


async def test_debugger_retries_flat_file_change_with_full_schema_feedback(tmp_path: Any) -> None:
    invalid: dict[str, Any] = {
        "path": "src/service.py",
        "operation": "modify",
        "content": "def repaired(): return True",
    }
    valid: dict[str, Any] = {
        "strategy": "Correct the validation condition.",
        "code_slice": "def validate(): return True",
        "error_excerpt": "Validation failed.",
        "proposed_changes": [
            {
                "path": "src/service.py",
                "operation": "modify",
                "content": "def repaired(): return True",
            }
        ],
        "model": "",
    }

    class ScriptedBackend:
        def __init__(self) -> None:
            self.calls: list[dict[str, Any]] = []
            self.outputs = [json.dumps(invalid), json.dumps(valid)]

        def __call__(self, **kwargs: Any) -> RawCompletion:
            self.calls.append(kwargs)
            return RawCompletion(text=self.outputs.pop(0))

    backend = ScriptedBackend()
    store = ConversationStore(tmp_path / "debug-conversation")
    active_router = LLMRouter(
        registry=fake_registry(),
        settings=fake_settings(Settings.from_env({})),
        backend=backend,
        conversation_store=store,
    )
    agent = DebuggerAgent(active_router)
    engine = SopEngine(
        agents={"debugger": agent},
        schemas={"debug_patch": DebugPatch},
        gates={},
    )
    step = SopStep(
        step_id="debug",
        agent="debugger",
        input={
            "report": {"error": "Validation failed."},
            "code": {"patch_id": "PATCH-1", "requirement_id": "REQ-1"},
        },
        output_schema="debug_patch",
        retries=1,
    )

    result = await engine._run_step(step, {}, {})

    assert isinstance(result.output, DebugPatch)
    assert result.output.patch_id == "PATCH-1-debug-2"
    assert result.output.requirement_id == "REQ-1"
    assert result.output.attempt == 2
    assert result.attempts == 2
    system_prompt = backend.calls[0]["messages"][0]["content"]
    second_prompt = backend.calls[1]["messages"][1]["content"]
    schema = DebugPatch.model_json_schema()
    assert '"required"' in system_prompt
    assert '"proposed_changes"' in system_prompt
    assert '"FileChange"' in system_prompt
    assert '"operation"' in system_prompt
    assert '"enum"' in system_prompt
    assert "Concrete valid JSON example generated from this schema" in system_prompt
    assert '"patch_id":' not in system_prompt.split("Output contract generated", 1)[1].split(
        "Concrete valid JSON example", 1
    )[0]
    assert "patch_id" in second_prompt
    assert "Extra inputs are not permitted" in second_prompt
    assert json.dumps(invalid) in second_prompt
    assert "return the complete output JSON" in second_prompt
    with pytest.raises(ValidationError):
        DebugPatch.model_validate(invalid)

    failures = [
        record for record in store.read_all() if record.metadata.get("error_type")
    ]
    assert len(failures) == 1
    assert failures[0].metadata["error_type"] == "ValidationError"
    assert failures[0].model == "fake/debugger"
    assert failures[0].latency_ms >= 0
    assert failures[0].attempt == 1
    assert schema["title"] == "DebugPatch"


def test_every_agent_prompt_example_is_generated_from_its_response_schema() -> None:
    for agent_type in (RequirementsAgent, CoderAgent, TestDesignerAgent, DebuggerAgent):
        response_schema = agent_type.response_schema or agent_type.schema
        example = _example_from_schema(response_schema.model_json_schema())
        parsed = response_schema.model_validate(example)
        assert isinstance(parsed, response_schema)
