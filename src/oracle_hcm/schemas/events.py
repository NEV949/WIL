"""Audit event shape used by the hash-chained event log."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field

__all__ = ["AuditEvent", "Checkpoint"]


class AuditEvent(BaseModel):
    """One link of the audit chain.

    The hash covers prev_hash, so any edit to an earlier event invalidates
    every later hash.
    """

    model_config = ConfigDict(extra="forbid")

    event_id: str
    seq: int = Field(ge=0)
    timestamp: str
    tenant_id: str
    actor: str
    action: str
    payload: dict[str, Any] = Field(default_factory=dict)
    prev_hash: str
    hash: str


class Checkpoint(BaseModel):
    """A signed assertion about the chain head at a point in time."""

    model_config = ConfigDict(extra="forbid")

    seq: int = Field(ge=0)
    head_hash: str
    signed_at: str
    signature: str
