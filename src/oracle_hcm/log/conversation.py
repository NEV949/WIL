"""Conversation store.

Every model call is recorded. Prompt and response text is redacted and stored
in content-addressed files; the record references those files by hash.
"""

from __future__ import annotations

import json
import threading
import uuid
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from oracle_hcm.canonical import sha256_hex
from oracle_hcm.redaction import redact, redact_text
from oracle_hcm.schemas.artifacts import utc_now_iso

__all__ = ["ConversationRecord", "ConversationStore"]


class ConversationRecord(BaseModel):
    """Metadata of one model call."""

    model_config = ConfigDict(extra="forbid")

    call_id: str
    timestamp: str
    tenant_id: str
    role: str
    model: str
    model_version: str = ""
    parameters: dict[str, Any] = Field(default_factory=dict)
    attempt: int = Field(default=1, ge=1)
    latency_ms: int = Field(default=0, ge=0)
    correlation_id: str = ""
    run_id: str = ""
    prompt_hash: str
    response_hash: str
    prompt_tokens: int = Field(default=0, ge=0)
    completion_tokens: int = Field(default=0, ge=0)
    total_tokens: int = Field(default=0, ge=0)
    metadata: dict[str, Any] = Field(default_factory=dict)


class ConversationStore:
    """Filesystem-backed store of redacted model transcripts."""

    def __init__(self, root: Path) -> None:
        self._root = root
        self._texts = root / "texts"
        self._records = root / "records"
        self._lock = threading.Lock()

    @property
    def root(self) -> Path:
        return self._root

    def _write_text(self, text: str) -> str:
        digest = sha256_hex(text.encode("utf-8"))
        self._texts.mkdir(parents=True, exist_ok=True)
        path = self._texts / f"{digest}.txt"
        if not path.exists():
            path.write_text(text, encoding="utf-8")
        return digest

    def store(
        self,
        *,
        tenant_id: str,
        role: str,
        model: str,
        prompt: str,
        response: str,
        prompt_tokens: int = 0,
        completion_tokens: int = 0,
        model_version: str = "",
        parameters: Mapping[str, Any] | None = None,
        attempt: int = 1,
        latency_ms: int = 0,
        correlation_id: str = "",
        run_id: str = "",
        error_type: str = "",
        error: str = "",
        metadata: Mapping[str, Any] | None = None,
    ) -> ConversationRecord:
        """Record one call, redacting both sides of the exchange."""
        clean_prompt = redact_text(prompt)
        clean_response = redact_text(response)
        with self._lock:
            prompt_hash = self._write_text(clean_prompt)
            response_hash = self._write_text(clean_response)
            clean_metadata = redact(dict(metadata or {}))
            if not isinstance(clean_metadata, dict):
                clean_metadata = {}
            record = ConversationRecord(
                call_id=uuid.uuid4().hex,
                timestamp=utc_now_iso(),
                tenant_id=tenant_id,
                role=role,
                model=model,
                model_version=model_version,
                parameters=dict(parameters or {}),
                attempt=attempt,
                latency_ms=latency_ms,
                correlation_id=correlation_id,
                run_id=run_id,
                prompt_hash=prompt_hash,
                response_hash=response_hash,
                prompt_tokens=prompt_tokens,
                completion_tokens=completion_tokens,
                total_tokens=prompt_tokens + completion_tokens,
                metadata={
                    **clean_metadata,
                    **({"error_type": error_type} if error_type else {}),
                    **({"error": redact_text(error)} if error else {}),
                },
            )
            self._records.mkdir(parents=True, exist_ok=True)
            (self._records / f"{record.call_id}.json").write_text(
                json.dumps(record.model_dump(mode="json"), sort_keys=True), encoding="utf-8"
            )
        return record

    def text_for(self, content_hash: str) -> str:
        """Read back a stored text by its content hash."""
        path = self._texts / f"{content_hash}.txt"
        if not path.is_file():
            raise KeyError(f"no stored text for hash {content_hash}")
        return path.read_text(encoding="utf-8")

    def read_all(self) -> list[ConversationRecord]:
        if not self._records.is_dir():
            return []
        records: list[ConversationRecord] = []
        for path in sorted(self._records.glob("*.json")):
            records.append(ConversationRecord.model_validate_json(path.read_text(encoding="utf-8")))
        return records
