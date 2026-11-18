"""Hash-chained audit event log.

Only the orchestrator writes this log. Each entry carries the hash of the
previous entry, so any edit to history invalidates every later hash.
"""

from __future__ import annotations

import os
import threading
import uuid
from collections.abc import Mapping
from pathlib import Path
from typing import TYPE_CHECKING, Any

from oracle_hcm.canonical import canonical_bytes, sha256_hex
from oracle_hcm.schemas.artifacts import utc_now_iso
from oracle_hcm.schemas.events import AuditEvent, Checkpoint

if TYPE_CHECKING:
    from oracle_hcm.signing.signer import Signer, Verifier

__all__ = [
    "GENESIS_HASH",
    "ORCHESTRATOR_ROLE",
    "SIGNATURE_KEY",
    "EventLog",
    "compute_event_hash",
    "signed_event_body",
    "verify_checkpoint",
    "verify_event_signature",
]

GENESIS_HASH = "0" * 64
ORCHESTRATOR_ROLE = "orchestrator"
SIGNATURE_KEY = "signature"


def compute_event_hash(event: AuditEvent) -> str:
    """Hash of an event body, covering prev_hash so the chain is linked."""
    body = event.model_dump(mode="json", exclude={"hash"})
    return sha256_hex(canonical_bytes(body))


def signed_event_body(event: AuditEvent) -> bytes:
    """The bytes an event signature covers.

    The signature itself is not part of the body, so the body can be rebuilt
    from the stored event.
    """
    payload = {key: value for key, value in event.payload.items() if key != SIGNATURE_KEY}
    return canonical_bytes(
        {
            "event_id": event.event_id,
            "seq": event.seq,
            "timestamp": event.timestamp,
            "tenant_id": event.tenant_id,
            "actor": event.actor,
            "action": event.action,
            "payload": payload,
            "prev_hash": event.prev_hash,
        }
    )


def verify_event_signature(event: AuditEvent, verifier: Verifier) -> bool:
    """Check the detached signature of one event."""
    signature = event.payload.get(SIGNATURE_KEY)
    if not isinstance(signature, str) or not signature:
        return False
    return verifier.verify(signed_event_body(event), signature)


class EventLog:
    """Append-only JSONL log with a SHA-256 hash chain."""

    def __init__(
        self,
        path: Path,
        *,
        role: str = ORCHESTRATOR_ROLE,
        fsync: bool = True,
    ) -> None:
        self._path = path
        self._role = role
        self._fsync = fsync
        self._lock = threading.Lock()

    @property
    def path(self) -> Path:
        return self._path

    def append(
        self,
        *,
        tenant_id: str,
        actor: str,
        action: str,
        payload: Mapping[str, Any] | None = None,
        signer: Signer | None = None,
    ) -> AuditEvent:
        """Append one event and return it.

        When a signer is given, the event carries a signature over its own
        body. The signature is stored in the payload, and the hash chain
        covers it.
        """
        if self._role != ORCHESTRATOR_ROLE:
            raise PermissionError(
                f"only the {ORCHESTRATOR_ROLE!r} may write the audit event log, got {self._role!r}"
            )
        with self._lock:
            seq, prev_hash = self._tail()
            event = AuditEvent(
                event_id=uuid.uuid4().hex,
                seq=seq,
                timestamp=utc_now_iso(),
                tenant_id=tenant_id,
                actor=actor,
                action=action,
                payload=dict(payload or {}),
                prev_hash=prev_hash,
                hash="",
            )
            if signer is not None:
                event.payload[SIGNATURE_KEY] = signer.sign(signed_event_body(event))
            event.hash = compute_event_hash(event)
            self._path.parent.mkdir(parents=True, exist_ok=True)
            with self._path.open("a", encoding="utf-8") as handle:
                handle.write(event.model_dump_json() + "\n")
                handle.flush()
                if self._fsync:
                    os.fsync(handle.fileno())
            return event

    def _tail(self) -> tuple[int, str]:
        events = self.read_all()
        if not events:
            return 0, GENESIS_HASH
        last = events[-1]
        return last.seq + 1, last.hash

    def read_all(self) -> list[AuditEvent]:
        if not self._path.is_file():
            return []
        events: list[AuditEvent] = []
        with self._path.open("r", encoding="utf-8") as handle:
            for line in handle:
                if line.strip():
                    events.append(AuditEvent.model_validate_json(line))
        return events

    def head_hash(self) -> str:
        events = self.read_all()
        return events[-1].hash if events else GENESIS_HASH

    def verify(self) -> bool:
        """Recompute the whole chain and check every link."""
        prev_hash = GENESIS_HASH
        for expected_seq, event in enumerate(self.read_all()):
            if event.seq != expected_seq or event.prev_hash != prev_hash:
                return False
            if compute_event_hash(event) != event.hash:
                return False
            prev_hash = event.hash
        return True

    def verify_signatures(self, verifier: Verifier) -> list[str]:
        """The actions of the signed events whose signature does not verify."""
        broken: list[str] = []
        for event in self.read_all():
            if SIGNATURE_KEY not in event.payload:
                continue
            if not verify_event_signature(event, verifier):
                broken.append(event.action)
        return broken

    def contains_hash(self, event_hash: str) -> bool:
        """Whether the chain still extends from this hash.

        The hash of the first event is not enough: the chain may have grown
        since it was pinned, so the link of the first event counts as well.
        """
        events = self.read_all()
        if not events:
            return event_hash == GENESIS_HASH
        if events[0].prev_hash == event_hash:
            return True
        return any(event.hash == event_hash for event in events)

    def checkpoint(self, signer: Signer, checkpoint_dir: Path | None = None) -> Checkpoint:
        """Sign the current chain head and persist the checkpoint."""
        events = self.read_all()
        seq = events[-1].seq if events else 0
        head_hash = events[-1].hash if events else GENESIS_HASH
        signed_at = utc_now_iso()
        body = canonical_bytes({"seq": seq, "head_hash": head_hash, "signed_at": signed_at})
        checkpoint = Checkpoint(
            seq=seq,
            head_hash=head_hash,
            signed_at=signed_at,
            signature=signer.sign(body),
        )
        target = checkpoint_dir if checkpoint_dir is not None else self._path.parent / "checkpoints"
        target.mkdir(parents=True, exist_ok=True)
        (target / f"{seq:08d}.json").write_text(checkpoint.model_dump_json(), encoding="utf-8")
        return checkpoint


def verify_checkpoint(checkpoint: Checkpoint, verifier: Verifier) -> bool:
    """Verify a checkpoint's detached signature."""
    body = canonical_bytes(
        {
            "seq": checkpoint.seq,
            "head_hash": checkpoint.head_hash,
            "signed_at": checkpoint.signed_at,
        }
    )
    return verifier.verify(body, checkpoint.signature)
