"""Test designer agent: turns a specification into a TestSuite."""

from __future__ import annotations

import json
from typing import Any, ClassVar

from oracle_hcm.agents.base import ArtifactAgent, spec_query
from oracle_hcm.config.models import ModelRole
from oracle_hcm.schemas.artifacts import TestSuite

__all__ = ["TestDesignerAgent"]


class TestDesignerAgent(ArtifactAgent):
    """Writes the tests that prove the specification is met."""

    role: ClassVar[ModelRole] = ModelRole.TEST_DESIGNER
    schema: ClassVar[type[TestSuite]] = TestSuite

    system_prompt: ClassVar[str] = (
        "You write tests for an approved specification. Return one complete TestSuite JSON "
        "object matching the generated Pydantic output contract. The kind field must use "
        "one of its exact allowed schema values. Large-scale or performance-style checks "
        "must use kind property or unit. Derive every import, module path, symbol name, "
        "call signature, input type, and result assertion from the supplied implementation. "
        "Do not invent a module or API that the implementation does not provide. Tests must "
        "be deterministic and must reference the requirement ids they cover."
    )

    def build_prompt(self, payload: dict[str, Any]) -> str:
        spec = payload.get("spec", {})
        code = payload.get("code", {})
        plan = payload.get("plan")
        parts = [
            "Write the test suite for this specification.",
            f"Specification: {json.dumps(spec, ensure_ascii=False)}",
            "Implementation to test (use its actual file paths and public interfaces): "
            + json.dumps(code, ensure_ascii=False),
        ]
        if plan is not None:
            parts.append(f"Plan: {json.dumps(plan, ensure_ascii=False)}")
        quality = payload.get("quality_feedback")
        if isinstance(quality, dict):
            parts.extend(
                [
                    "COVERAGE REPAIR: add meaningful deterministic tests for uncovered "
                    "code paths and edge cases. Do not reduce the coverage threshold or "
                    "weaken existing assertions.",
                    "Coverage findings: " + json.dumps(quality, ensure_ascii=False),
                ]
            )
        context = self.knowledge_context(payload, spec_query(spec))
        if context:
            parts.append(context)
        parts.append("Every test must cover at least one acceptance criterion.")
        return "\n".join(parts)
