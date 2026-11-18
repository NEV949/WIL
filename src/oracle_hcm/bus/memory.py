"""In-process bus.

Used by tests and by single-process runs; it enforces exactly the same
signature, tenant and schema checks as the Redis backend.
"""

from __future__ import annotations

import asyncio
import uuid

from oracle_hcm.bus.base import Bus
from oracle_hcm.errors import EnvelopeVerificationError
from oracle_hcm.schemas.envelope import Envelope
from oracle_hcm.signing.signer import Signer, Verifier

__all__ = ["InMemoryBus"]


class InMemoryBus(Bus):
    """Queue-backed bus."""

    def __init__(self, *, signer: Signer, verifier: Verifier) -> None:
        super().__init__(signer=signer, verifier=verifier)
        self._queue: asyncio.Queue[Envelope] = asyncio.Queue()
        self.rejected: list[Envelope] = []

    async def publish(self, envelope: Envelope) -> str:
        signed = self.sign_envelope(envelope)
        await self._queue.put(signed)
        return signed.id

    async def poll(
        self,
        *,
        consumer: str,
        tenant_id: str | None = None,
        count: int = 10,
        block_ms: int = 1000,
    ) -> list[Envelope]:
        received: list[Envelope] = []
        while len(received) < count:
            try:
                envelope = self._queue.get_nowait()
            except asyncio.QueueEmpty:
                break
            try:
                received.append(self.verify_envelope(envelope, expected_tenant=tenant_id))
            except EnvelopeVerificationError:
                self.rejected.append(envelope)
        return received

    async def publish_raw(self, envelope: Envelope) -> str:
        """Publish without signing, to exercise the receive-side checks."""
        await self._queue.put(envelope)
        return envelope.id


def new_envelope(
    *,
    type_name: str,
    payload: dict[str, object],
    tenant_id: str = "default",
    sender: str = "test",
    correlation_id: str | None = None,
) -> Envelope:
    """Build an envelope for tests and local runs."""
    return Envelope(
        type=type_name,
        id=uuid.uuid4().hex,
        correlation_id=correlation_id or uuid.uuid4().hex,
        tenant_id=tenant_id,
        sender=sender,
        timestamp="2026-01-01T00:00:00+00:00",
        payload=payload,
    )
