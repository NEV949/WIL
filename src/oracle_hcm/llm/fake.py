"""A backend that never touches the network.

The fake backend answers every call with a scripted JSON document. It lets
the whole pipeline - agents, approvals, sandbox, debug loop - run end to end
without a provider key and without a single live model call.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field, replace
from typing import Any

from oracle_hcm.config.models import ModelRegistry, ModelRole, ModelSpec
from oracle_hcm.config.providers import Provider
from oracle_hcm.config.settings import Settings
from oracle_hcm.llm.router import RawCompletion

__all__ = [
    "FAKE_MODELS",
    "FakeBackend",
    "fake_registry",
    "fake_settings",
]

FAKE_MODELS: dict[ModelRole, str] = {
    ModelRole.REQUIREMENTS: "fake/requirements",
    ModelRole.CODER: "fake/coder",
    ModelRole.DEBUGGER: "fake/debugger",
    ModelRole.TEST_DESIGNER: "fake/test-designer",
}

FAKE_KEY = "not-used-by-fake-backend"

DEFAULT_REQUIREMENTS_PAYLOAD: dict[str, Any] = {
    "requirement_id": "REQ-1",
    "title": "Add overtime calculation",
    "description": "Calculate overtime for monthly staff from their timesheet.",
    "acceptance_criteria": [
        "Overtime is paid at 1.5x the hourly rate.",
        "A timesheet without overtime produces no overtime pay.",
    ],
    "domain_entities": ["Timesheet", "PayrollRun"],
    "constraints": ["Hourly rate is taken from the salary assignment."],
    "non_functional_requirements": ["The calculation completes in under 100 ms."],
    "risk_keywords": ["payroll", "money"],
    "source": "operator",
}

DEFAULT_CODE_PAYLOAD: dict[str, Any] = {
    "patch_id": "PATCH-1",
    "requirement_id": "REQ-1",
    "summary": "Add the overtime helper module.",
    "files": [
        {
            "path": "pkg/overtime.py",
            "operation": "create",
            "content": (
                "def overtime_pay(hours: float, rate: float) -> float:\n"
                '    """Pay 1.5x for every hour above the weekly threshold."""\n'
                "    regular = min(hours, 40.0)\n"
                "    extra = max(hours - 40.0, 0.0)\n"
                "    return regular * rate + extra * rate * 1.5\n"
            ),
        }
    ],
}

DEFAULT_TEST_PAYLOAD: dict[str, Any] = {
    "suite_id": "SUITE-1",
    "requirement_id": "REQ-1",
    "tests": [
        {
            "test_id": "test-overtime-pay",
            "requirement_ids": ["REQ-1"],
            "target_module": "pkg.overtime",
            "test_code": (
                "from pkg.overtime import overtime_pay\n"
                "\n"
                "\n"
                "def test_overtime_is_paid_at_one_and_a_half():\n"
                "    assert overtime_pay(45.0, 10.0) == 475.0\n"
            ),
            "kind": "unit",
            "deterministic": True,
            "seed": 7,
        }
    ],
}

DEFAULT_DEBUG_PAYLOAD: dict[str, Any] = {
    "strategy": "Correct the boundary comparison in the overtime helper.",
    "code_slice": "extra = max(hours - 40.0, 0.0)",
    "error_excerpt": "AssertionError: expected 475.0, got 450.0",
    "proposed_changes": [
        {
            "path": "pkg/overtime.py",
            "operation": "modify",
            "content": (
                "def overtime_pay(hours: float, rate: float) -> float:\n"
                '    """Pay 1.5x for every hour above the weekly threshold."""\n'
                "    regular = min(hours, 40.0)\n"
                "    extra = max(hours - 40.0, 0.0)\n"
                "    return regular * rate + extra * rate * 1.5\n"
            ),
        }
    ],
    "model": "fake/debugger",
}

DEFAULT_PAYLOADS: dict[str, dict[str, Any]] = {
    "requirements": DEFAULT_REQUIREMENTS_PAYLOAD,
    "coder": DEFAULT_CODE_PAYLOAD,
    "test-designer": DEFAULT_TEST_PAYLOAD,
    "debugger": DEFAULT_DEBUG_PAYLOAD,
}


@dataclass
class FakeBackend:
    """Answers with scripted payloads keyed by the fake model suffix."""

    payloads: dict[str, dict[str, Any]] = field(default_factory=lambda: dict(DEFAULT_PAYLOADS))
    calls: list[dict[str, Any]] = field(default_factory=list)

    def payload_for(self, model: str) -> dict[str, Any]:
        suffix = model.split("/", 1)[1] if "/" in model else model
        try:
            return self.payloads[suffix]
        except KeyError as exc:
            raise KeyError(f"no scripted payload for model '{model}'") from exc

    def __call__(
        self,
        *,
        model: str,
        messages: list[dict[str, str]],
        api_key: str,
        temperature: float | None = None,
        max_tokens: int | None = None,
        timeout: float = 90.0,
        **kwargs: Any,
    ) -> RawCompletion:
        call: dict[str, Any] = {
            "model": model,
            "api_key": api_key,
            "max_tokens": max_tokens,
            "timeout": timeout,
            "prompt": messages[-1]["content"] if messages else "",
        }
        if temperature is not None:
            call["temperature"] = temperature
        call.update(kwargs)
        self.calls.append(call)
        text = json.dumps(self.payload_for(model))
        return RawCompletion(
            text=text,
            prompt_tokens=len(messages) * 32,
            completion_tokens=len(text) // 4,
        )


def fake_registry() -> ModelRegistry:
    """Model registry that points every role at the fake backend."""
    return ModelRegistry(
        version=1,
        roles={
            role: ModelSpec(model=model, provider=Provider.FAKE, rpm=1000, tpm=1_000_000)
            for role, model in FAKE_MODELS.items()
        },
    )


def fake_settings(settings: Settings) -> Settings:
    """Settings with a placeholder credential for the fake provider."""
    keys = dict(settings.api_keys)
    keys[Provider.FAKE.value] = FAKE_KEY
    return replace(settings, api_keys=keys)
