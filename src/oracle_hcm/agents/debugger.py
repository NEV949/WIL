"""Debugger agent: turns a failed run into a DebugPatch."""

from __future__ import annotations

import json
from copy import deepcopy
from typing import Any, ClassVar, cast

from pydantic import BaseModel, ConfigDict, create_model

from oracle_hcm.agents.base import ArtifactAgent, spec_query
from oracle_hcm.config.models import ModelRole
from oracle_hcm.schemas.artifacts import DebugPatch

__all__ = ["DebuggerAgent"]

_ENGINE_FIELDS = frozenset({"patch_id", "requirement_id", "attempt"})
_DEBUG_CONTENT_FIELDS = {
    name: (field.annotation, deepcopy(field))
    for name, field in DebugPatch.model_fields.items()
    if name not in _ENGINE_FIELDS
}
DebugPatchContent = create_model(
    "DebugPatchContent",
    __config__=ConfigDict(extra="forbid"),
    **cast("dict[str, Any]", _DEBUG_CONTENT_FIELDS),
)


class DebuggerAgent(ArtifactAgent):
    """Diagnoses a failing sandbox run and proposes the repair."""

    role: ClassVar[ModelRole] = ModelRole.DEBUGGER
    schema: ClassVar[type[DebugPatch]] = DebugPatch
    response_schema: ClassVar[type[BaseModel]] = DebugPatchContent

    system_prompt: ClassVar[str] = (
        "You repair a failing test run. Return only the change-content object defined by "
        "the generated Pydantic response contract. The engine supplies patch_id, "
        "requirement_id, and attempt; do not include those engine-owned fields. Put file "
        "changes only inside proposed_changes, following its exact nested structure. Include "
        "the full corrected file content for each changed file."
    )

    def finalize_output(self, output: BaseModel, payload: dict[str, Any]) -> BaseModel:
        """Inject identifiers owned by the execution engine before strict validation."""
        code = payload.get("code", {})
        if isinstance(code, BaseModel):
            code = code.model_dump(mode="python")
        code = code if isinstance(code, dict) else {}
        requirement_id = str(code.get("requirement_id") or payload.get("requirement_id") or "")
        patch_id = str(code.get("patch_id") or "")
        attempt = int(payload.get("__engine_attempt__", 1))
        content = output.model_dump(mode="python")
        return DebugPatch.model_validate(
            {
                **content,
                "patch_id": f"{patch_id}-debug-{attempt}" if patch_id else f"DEBUG-{attempt}",
                "requirement_id": requirement_id,
                "attempt": attempt,
            }
        )

    def build_prompt(self, payload: dict[str, Any]) -> str:
        report = payload.get("report", {})
        code = payload.get("code", {})
        parts = [
            "Diagnose this failure and propose the repair.",
            f"Execution report: {json.dumps(report, ensure_ascii=False)}",
            f"Current code patch: {json.dumps(code, ensure_ascii=False)}",
        ]
        repair = payload.get("security_repair")
        if isinstance(repair, dict):
            parts.append(
                "Security repair fallback: resolve these findings without bypassing the "
                "security checks, preserve the original requirements, and account for "
                "the Coder repair attempt. Findings and history: "
                + json.dumps(repair, ensure_ascii=False)
            )
        context = self.knowledge_context(payload, spec_query(payload.get("spec", {})))
        if context:
            parts.append(context)
        parts.append("Return the corrected content of every file you change.")
        return "\n".join(parts)
