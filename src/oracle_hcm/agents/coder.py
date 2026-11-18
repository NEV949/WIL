"""Coder agent: turns a specification into a CodePatch."""

from __future__ import annotations

import json
from typing import Any, ClassVar

from oracle_hcm.agents.base import ArtifactAgent, spec_query
from oracle_hcm.config.models import ModelRole
from oracle_hcm.schemas.artifacts import CodePatch

__all__ = ["CoderAgent"]


class CoderAgent(ArtifactAgent):
    """Writes the file changes that implement the approved specification."""

    role: ClassVar[ModelRole] = ModelRole.CODER
    schema: ClassVar[type[CodePatch]] = CodePatch

    system_prompt: ClassVar[str] = (
        "You implement an approved specification. Return one complete CodePatch JSON "
        "object matching the generated Pydantic output contract. File paths must be "
        "relative and must not traverse upwards. Every function, parameter, and return "
        "value must be strictly typed; parameterize all generic types such as dict, list, "
        "and set so the complete output passes mypy --strict."
    )

    def build_prompt(self, payload: dict[str, Any]) -> str:
        spec = payload.get("spec", {})
        plan = payload.get("plan")
        parts = [
            "Implement this specification.",
            f"Specification: {json.dumps(spec, ensure_ascii=False)}",
        ]
        if plan is not None:
            parts.append(f"Plan: {json.dumps(plan, ensure_ascii=False)}")
        repair = payload.get("security_repair")
        if isinstance(repair, dict):
            parts.extend(
                [
                    "SECURITY REPAIR: resolve every listed finding without suppressing, "
                    "ignoring, downgrading, or bypassing any security rule. Preserve all "
                    "original functional requirements and existing behavior.",
                    "Security findings and prior repair history: "
                    + json.dumps(repair, ensure_ascii=False),
                    "Latest implementation and related generated files: "
                    + json.dumps(payload.get("current_code", {}), ensure_ascii=False),
                    "Current generated tests: "
                    + json.dumps(payload.get("tests", {}), ensure_ascii=False),
                ]
            )
        quality = payload.get("quality_feedback")
        if isinstance(quality, dict):
            parts.extend(
                [
                    "QUALITY REPAIR: correct the supplied mypy and coverage diagnostics "
                    "while preserving approved functional requirements and schemas.",
                    "Quality findings: " + json.dumps(quality, ensure_ascii=False),
                    "Latest implementation and tests: "
                    + json.dumps(payload.get("current_code", {}), ensure_ascii=False),
                ]
            )
        context = self.knowledge_context(payload, spec_query(spec))
        if context:
            parts.append(context)
        parts.append("Return the complete file contents for every file you touch.")
        return "\n".join(parts)
