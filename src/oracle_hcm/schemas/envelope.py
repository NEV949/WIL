"""Signed bus envelope.

Wire format uses JSON-LD style keys (@context, @type); Python code uses the
plain attribute names.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from oracle_hcm.canonical import canonical_bytes

__all__ = ["DEFAULT_CONTEXT", "Envelope"]


DEFAULT_CONTEXT = "https://oracle-hcm.engine/bus/v1"


class Envelope(BaseModel):
    """A message carried on the bus."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    context: str = Field(default=DEFAULT_CONTEXT, alias="@context")
    type: str = Field(alias="@type")
    id: str
    correlation_id: str
    tenant_id: str
    sender: str
    timestamp: str
    payload: dict[str, Any] = Field(default_factory=dict)
    signature: str = ""

    def signing_payload(self) -> bytes:
        """Canonical bytes that the signature covers (signature excluded)."""
        data = self.model_dump(mode="json", by_alias=True, exclude={"signature"})
        return canonical_bytes(data)
