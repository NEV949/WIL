"""Requirements agent: turns a request text into a RequirementSpec."""

from __future__ import annotations

from typing import Any, ClassVar

from oracle_hcm.agents.base import ArtifactAgent
from oracle_hcm.config.models import ModelRole
from oracle_hcm.knowledge.retrieval import query_terms
from oracle_hcm.schemas.artifacts import RequirementSpec

__all__ = ["RequirementsAgent"]


class RequirementsAgent(ArtifactAgent):
    """Normalises a free text request into a reviewable specification."""

    role: ClassVar[ModelRole] = ModelRole.REQUIREMENTS
    schema: ClassVar[type[RequirementSpec]] = RequirementSpec

    system_prompt: ClassVar[str] = (
        "You turn a software request into a precise specification. Return one complete "
        "RequirementSpec JSON object matching the generated Pydantic output contract."
    )

    def build_prompt(self, payload: dict[str, Any]) -> str:
        request = str(payload.get("request", ""))
        parts = [
            "Write the specification for this request.",
            f"Request: {request}",
            "List at least one acceptance criterion. Mark money, payroll, access and "
            "deletion concerns in risk_keywords.",
        ]
        affected = self.impact_context(payload, query_terms(request))
        if affected:
            parts.append(
                "These files of the repository would be affected by the request: "
                + ", ".join(affected)
            )
        context = self.knowledge_context(payload, request)
        if context:
            parts.append(context)
        return "\n".join(parts)
