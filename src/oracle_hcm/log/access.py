"""Access log: logins, approvals and other human interactions.

The access log is a second, separate chain next to the audit log. It records
who did what from where: the user, the tenant, the address of the client and
the moment. Every entry carries the hash of the previous one, so an entry that
is edited or removed breaks the chain that follows it.

An entry names the user and the correlation id of the request, so it can be
joined with the audit log, which carries the same correlation id.
"""

from __future__ import annotations

import os
import threading
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from oracle_hcm.canonical import canonical_bytes, sha256_hex
from oracle_hcm.schemas.artifacts import utc_now_iso

__all__ = [
    "ACCESS_GENESIS_HASH",
    "AccessLog",
    "AccessRecord",
    "compute_record_hash",
]

Result = Literal["success", "failure", "denied"]

ACCESS_GENESIS_HASH = "0" * 64


class AccessRecord(BaseModel):
    """One access event."""

    model_config = ConfigDict(extra="forbid")

    seq: int = Field(ge=0)
    timestamp: str
    user_id: str
    action: str
    target: str
    result: Result
    tenant_id: str = "default"
    ip: str | None = None
    correlation_id: str = ""
    detail: str = ""
    prev_hash: str
    hash: str = ""


def compute_record_hash(record: AccessRecord) -> str:
    """Hash of an access record, covering prev_hash so the chain is linked."""
    body = record.model_dump(mode="json", exclude={"hash"})
    return sha256_hex(canonical_bytes(body))


class AccessLog:
    """Append-only JSONL access log with a SHA-256 hash chain."""

    def __init__(self, path: Path) -> None:
        self._path = path
        self._lock = threading.Lock()

    @property
    def path(self) -> Path:
        return self._path

    def record(
        self,
        *,
        user_id: str,
        action: str,
        target: str,
        result: Result,
        tenant_id: str = "default",
        ip: str | None = None,
        correlation_id: str = "",
        detail: str = "",
    ) -> AccessRecord:
        """Append one entry and return it."""
        with self._lock:
            seq, prev_hash = self._tail()
            entry = AccessRecord(
                seq=seq,
                timestamp=utc_now_iso(),
                user_id=user_id,
                action=action,
                target=target,
                result=result,
                tenant_id=tenant_id,
                ip=ip,
                correlation_id=correlation_id,
                detail=detail,
                prev_hash=prev_hash,
                hash="",
            )
            entry.hash = compute_record_hash(entry)
            self._path.parent.mkdir(parents=True, exist_ok=True)
            with self._path.open("a", encoding="utf-8") as handle:
                handle.write(entry.model_dump_json() + "\n")
                handle.flush()
                os.fsync(handle.fileno())
            return entry

    def _tail(self) -> tuple[int, str]:
        entries = self.read_all()
        if not entries:
            return 0, ACCESS_GENESIS_HASH
        last = entries[-1]
        return last.seq + 1, last.hash

    def read_all(self) -> list[AccessRecord]:
        if not self._path.is_file():
            return []
        entries: list[AccessRecord] = []
        with self._path.open("r", encoding="utf-8") as handle:
            for line in handle:
                if line.strip():
                    entries.append(AccessRecord.model_validate_json(line))
        return entries

    def verify(self) -> bool:
        """Recompute the whole chain and check every link."""
        prev_hash = ACCESS_GENESIS_HASH
        for expected_seq, entry in enumerate(self.read_all()):
            if entry.seq != expected_seq or entry.prev_hash != prev_hash:
                return False
            if compute_record_hash(entry) != entry.hash:
                return False
            prev_hash = entry.hash
        return True
