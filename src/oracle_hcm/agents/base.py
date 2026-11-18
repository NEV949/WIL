"""Shared plumbing for the artifact producing agents.

Every agent turns one input payload into exactly one of the six allowed
artifacts. The model is asked for a JSON document and the document is
validated against the artifact schema, so a malformed answer fails the step
instead of leaking into the rest of the pipeline.
"""

from __future__ import annotations

import json
from typing import Any, ClassVar, TypeVar

from pydantic import BaseModel, ValidationError

from oracle_hcm.config.models import ModelRole
from oracle_hcm.errors import OracleHcmError
from oracle_hcm.knowledge.retrieval import RetrievalHandle
from oracle_hcm.llm.router import CompletionRequest, LLMRouter
from oracle_hcm.redaction import redact_text

__all__ = [
    "AgentError",
    "ArtifactAgent",
    "extract_json_object",
    "spec_query",
]

ArtifactT = TypeVar("ArtifactT", bound=BaseModel)


def spec_query(spec: dict[str, Any]) -> str:
    """The query that describes a specification."""
    parts = [str(spec.get("title", "")), str(spec.get("description", ""))]
    names = [
        str(entity.get("name", ""))
        for entity in spec.get("entities", [])
        if isinstance(entity, dict)
    ]
    names.extend(str(name) for name in spec.get("domain_entities", []))
    parts.extend(names)
    return " ".join(part for part in parts if part)


class AgentError(OracleHcmError):
    """The agent produced something that is not a valid artifact."""

    def __init__(
        self,
        message: str,
        *,
        validation_error: str = "",
        invalid_output: str = "",
    ) -> None:
        super().__init__(message)
        self.validation_error = validation_error
        self.invalid_output = invalid_output


def _schema_enum_values(schema: dict[str, Any]) -> list[tuple[str, list[Any]]]:
    """Collect enum constraints from the complete Pydantic JSON schema."""
    found: list[tuple[str, list[Any]]] = []

    def visit(node: Any, path: str) -> None:
        if isinstance(node, dict):
            values = node.get("enum")
            if isinstance(values, list):
                found.append((path or "value", values))
            for key, value in node.items():
                if key != "enum":
                    visit(value, f"{path}.{key}" if path else key)
        elif isinstance(node, list):
            for index, value in enumerate(node):
                visit(value, f"{path}[{index}]")

    visit(schema, "")
    return found


def _example_from_schema(schema: dict[str, Any]) -> Any:
    """Build a concrete schema-shaped JSON example, including nested models."""
    definitions = schema.get("$defs", {})

    def value(node: Any) -> Any:
        if isinstance(node, list):
            return [value(item) for item in node]
        if not isinstance(node, dict):
            return None
        reference = node.get("$ref")
        if isinstance(reference, str):
            target: Any = schema
            for part in reference.lstrip("#/").split("/"):
                target = target[part] if isinstance(target, dict) else None
            return value(target)
        if "default" in node:
            return node["default"]
        if isinstance(node.get("enum"), list):
            return node["enum"][0]
        if "const" in node:
            return node["const"]
        choices = node.get("anyOf") or node.get("oneOf")
        if isinstance(choices, list):
            non_null = [item for item in choices if item.get("type") != "null"]
            return value(non_null[0] if non_null else choices[0])
        kind = node.get("type")
        if kind == "object" or "properties" in node:
            props = node.get("properties", {})
            required = set(node.get("required", []))
            return {
                key: value(field)
                for key, field in props.items()
                if key in required or "default" in field
            }
        if kind == "array":
            minimum = int(node.get("minItems", 0))
            return [value(node.get("items", {})) for _ in range(max(minimum, 1))]
        if kind == "string":
            formats = {
                "date-time": "2026-01-01T00:00:00Z",
                "date": "2026-01-01",
                "time": "12:00:00",
                "uuid": "00000000-0000-4000-8000-000000000000",
            }
            return formats.get(str(node.get("format", "")), "example")
        if kind == "integer":
            return int(node.get("minimum", 1))
        if kind == "number":
            return float(node.get("minimum", 1.0))
        if kind == "boolean":
            return True
        if kind == "null":
            return None
        for key in ("allOf",):
            if isinstance(node.get(key), list) and node[key]:
                merged: dict[str, Any] = {}
                for item in node[key]:
                    child = value(item)
                    if isinstance(child, dict):
                        merged.update(child)
                return merged
        return None

    del definitions  # Definitions are resolved through the root schema above.
    return value(schema)


def extract_json_object(text: str) -> dict[str, Any]:
    """Pull the first JSON object out of a model answer.

    Models often wrap JSON in a fenced code block or add a sentence of
    prose around it. The first balanced object in the text wins.
    """
    stripped = text.strip()
    if stripped.startswith("```"):
        stripped = stripped.strip("`")
        if stripped.lower().startswith("json"):
            stripped = stripped[4:]
        stripped = stripped.strip()
    try:
        parsed = json.loads(stripped)
    except json.JSONDecodeError:
        parsed = None
    if isinstance(parsed, dict):
        return parsed
    start = stripped.find("{")
    while start != -1:
        depth = 0
        in_string = False
        escaped = False
        for index in range(start, len(stripped)):
            char = stripped[index]
            if in_string:
                if escaped:
                    escaped = False
                elif char == "\\":
                    escaped = True
                elif char == '"':
                    in_string = False
                continue
            if char == '"':
                in_string = True
            elif char == "{":
                depth += 1
            elif char == "}":
                depth -= 1
                if depth == 0:
                    candidate = stripped[start : index + 1]
                    try:
                        decoded = json.loads(candidate)
                    except json.JSONDecodeError:
                        break
                    if isinstance(decoded, dict):
                        return decoded
                    break
        start = stripped.find("{", start + 1)
    raise AgentError("the model answer does not contain a JSON object")


class ArtifactAgent:
    """Calls a model and validates the answer against one artifact schema."""

    __test__: ClassVar[bool] = False

    role: ClassVar[ModelRole]
    schema: ClassVar[type[BaseModel]]
    response_schema: ClassVar[type[BaseModel] | None] = None
    system_prompt: ClassVar[str] = (
        "You are a careful engineering assistant. Answer with a single JSON object and "
        "nothing else."
    )

    def __init__(
        self,
        router: LLMRouter,
        *,
        tenant_id: str = "default",
        retrieval: RetrievalHandle | None = None,
    ) -> None:
        self._router = router
        self._tenant_id = tenant_id
        self._retrieval = retrieval

    def build_prompt(self, payload: dict[str, Any]) -> str:
        """Render the step input as the user message."""
        raise NotImplementedError

    def knowledge_context(self, payload: dict[str, Any], query: str) -> str:
        """The retrieved knowledge that may go into the prompt of the agent."""
        if self._retrieval is None:
            return ""
        return self._retrieval.context(
            query,
            tenant_id=self._tenant_of(payload),
            agent=self.role.value,
            run_id=str(payload.get("run_id", "")),
        )

    def impact_context(self, payload: dict[str, Any], terms: list[str]) -> list[str]:
        """The files that a change to the given symbols would affect."""
        if self._retrieval is None:
            return []
        tenant_id = self._tenant_of(payload)
        affected: set[str] = set()
        for term in terms:
            affected.update(self._retrieval.impact(term, tenant_id=tenant_id))
        return sorted(affected)

    def _tenant_of(self, payload: dict[str, Any]) -> str:
        """The tenant of the run the step belongs to."""
        return str(payload.get("tenant_id") or self._tenant_id)

    def finalize_output(self, output: BaseModel, payload: dict[str, Any]) -> BaseModel:
        """Convert a model-facing response into the engine-owned artifact."""
        return output

    async def __call__(self, payload: dict[str, Any]) -> BaseModel:
        request = CompletionRequest(
            role=self.role,
            messages=[
                {"role": "system", "content": self.system_prompt},
                {"role": "user", "content": self.build_prompt(payload)},
            ],
            tenant_id=self._tenant_of(payload),
            metadata={"run_id": str(payload.get("run_id", ""))},
        )
        response_schema = self.response_schema or self.schema
        schema = response_schema.model_json_schema()
        enum_values = _schema_enum_values(schema)
        if enum_values:
            enum_prompt = "Allowed enum/literal values from the output schema: " + "; ".join(
                f"{path}: {json.dumps(values, ensure_ascii=False)}" for path, values in enum_values
            )
            request.messages[0]["content"] += "\n" + enum_prompt
        request.messages[0]["content"] += (
            "\nOutput contract generated from the Pydantic schema. Return exactly one "
            "JSON object matching this complete schema, including required fields, types, "
            "descriptions, nesting, defaults, and allowed values. Do not add, rename, or "
            "move fields.\n"
            + json.dumps(schema, ensure_ascii=False, indent=2)
            + "\nConcrete valid JSON example generated from this schema:\n"
            + json.dumps(_example_from_schema(schema), ensure_ascii=False, indent=2)
        )
        retry = payload.get("__validation_retry__")
        user_prompt = self.build_prompt(payload)
        if isinstance(retry, dict):
            user_prompt += (
                "\nThe previous output failed schema validation. Correct it and return the "
                "complete output JSON, not a patch.\nValidation error: "
                + redact_text(str(retry.get("error", "")))
                + "\nPrevious invalid output (truncated):\n"
                + redact_text(str(retry.get("output", "")))
            )
        request.messages[1]["content"] = user_prompt
        completion = await self._router.complete(request)
        data = extract_json_object(completion.text)
        try:
            parsed = response_schema.model_validate(data)
            return self.schema.model_validate(
                self.finalize_output(parsed, payload).model_dump(mode="python")
            )
        except ValidationError as exc:
            error_text = str(exc)
            self._router.record_schema_failure(request, completion, error_text)
            raise AgentError(
                f"agent '{self.role.value}' produced an invalid "
                f"{self.schema.__name__}: {error_text}",
                validation_error=error_text,
                invalid_output=completion.text,
            ) from exc
