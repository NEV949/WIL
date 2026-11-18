"""Bus interface and envelope security.

A backend publishes and receives signed envelopes. On receipt the signature,
the tenant and the payload schema are verified before the message is handed
to the orchestrator.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from pydantic import BaseModel, ValidationError

from oracle_hcm.errors import EnvelopeVerificationError
from oracle_hcm.schemas.envelope import Envelope
from oracle_hcm.signing.signer import Signer, Verifier

__all__ = ["Bus"]


class Bus(ABC):
    """Transport for signed envelopes."""

    def __init__(self, *, signer: Signer, verifier: Verifier) -> None:
        self._signer = signer
        self._verifier = verifier
        self._schemas: dict[str, type[BaseModel]] = {}

    def register_schema(self, type_name: str, model: type[BaseModel]) -> None:
        """Bind an envelope type to the Pydantic model of its payload."""
        self._schemas[type_name] = model

    def sign_envelope(self, envelope: Envelope) -> Envelope:
        signed = envelope.model_copy(deep=True)
        signed.signature = self._signer.sign(signed.signing_payload())
        return signed

    def verify_envelope(
        self,
        envelope: Envelope,
        *,
        expected_tenant: str | None = None,
    ) -> Envelope:
        """Check signature, tenant and payload schema.

        Raises EnvelopeVerificationError on any failure.
        """
        if not self._verifier.verify(envelope.signing_payload(), envelope.signature):
            raise EnvelopeVerificationError(
                f"signature verification failed for envelope {envelope.id}"
            )
        if expected_tenant is not None and envelope.tenant_id != expected_tenant:
            raise EnvelopeVerificationError(
                f"envelope {envelope.id} belongs to tenant '{envelope.tenant_id}', "
                f"expected '{expected_tenant}'"
            )
        model = self._schemas.get(envelope.type)
        if model is not None:
            try:
                model.model_validate(envelope.payload)
            except ValidationError as exc:
                raise EnvelopeVerificationError(
                    f"payload of envelope {envelope.id} does not match schema '{envelope.type}'"
                ) from exc
        return envelope

    @abstractmethod
    async def publish(self, envelope: Envelope) -> str:
        """Publish an envelope and return the transport's receipt id."""

    @abstractmethod
    async def poll(
        self,
        *,
        consumer: str,
        tenant_id: str | None = None,
        count: int = 10,
        block_ms: int = 1000,
    ) -> list[Envelope]:
        """Receive verified envelopes."""
