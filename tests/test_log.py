"""Hash-chained audit log, access log and conversation store."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from oracle_hcm.log.access import ACCESS_GENESIS_HASH, AccessLog
from oracle_hcm.log.conversation import ConversationStore
from oracle_hcm.log.eventlog import GENESIS_HASH, EventLog, compute_event_hash, verify_checkpoint
from oracle_hcm.signing.signer import Signer, Verifier


def test_events_form_a_hash_chain(tmp_path: Path) -> None:
    log = EventLog(tmp_path / "audit.jsonl")
    first = log.append(tenant_id="t1", actor="orchestrator", action="spec.created")
    second = log.append(tenant_id="t1", actor="orchestrator", action="code.created")

    assert first.prev_hash == GENESIS_HASH
    assert second.prev_hash == first.hash
    assert log.head_hash() == second.hash
    assert log.verify() is True


def test_tampering_breaks_the_chain(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    log = EventLog(path)
    log.append(tenant_id="t1", actor="orchestrator", action="a")
    log.append(tenant_id="t1", actor="orchestrator", action="b")

    lines = path.read_text(encoding="utf-8").splitlines()
    payload = json.loads(lines[0])
    payload["action"] = "tampered"
    lines[0] = json.dumps(payload)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    assert log.verify() is False


def test_only_the_orchestrator_writes(tmp_path: Path) -> None:
    log = EventLog(tmp_path / "audit.jsonl", role="agent")
    with pytest.raises(PermissionError):
        log.append(tenant_id="t1", actor="agent", action="nope")


def test_checkpoint_signs_the_chain_head(
    tmp_path: Path, signer: Signer, verifier: Verifier
) -> None:
    log = EventLog(tmp_path / "audit.jsonl")
    log.append(tenant_id="t1", actor="orchestrator", action="a")
    checkpoint = log.checkpoint(signer)

    assert checkpoint.seq == 0
    assert checkpoint.head_hash == log.head_hash()
    assert verify_checkpoint(checkpoint, verifier) is True
    assert (tmp_path / "checkpoints" / "00000000.json").is_file()


def test_checkpoint_with_tampered_head_fails_verification(
    tmp_path: Path, signer: Signer, verifier: Verifier
) -> None:
    log = EventLog(tmp_path / "audit.jsonl")
    log.append(tenant_id="t1", actor="orchestrator", action="a")
    checkpoint = log.checkpoint(signer)
    checkpoint.head_hash = "0" * 64
    assert verify_checkpoint(checkpoint, verifier) is False


def test_event_hash_covers_the_payload(tmp_path: Path) -> None:
    log = EventLog(tmp_path / "audit.jsonl")
    event = log.append(tenant_id="t1", actor="orchestrator", action="a", payload={"x": 1})
    mutated = event.model_copy(update={"payload": {"x": 2}})
    assert compute_event_hash(mutated) != event.hash


def test_access_log_records_entries(tmp_path: Path) -> None:
    access = AccessLog(tmp_path / "access.jsonl")
    entry = access.record(
        user_id="admin",
        action="approve",
        target="spec:R-1",
        result="success",
        tenant_id="t1",
        ip="127.0.0.1",
    )
    assert entry.result == "success"
    assert entry.user_id == "admin"
    assert entry.tenant_id == "t1"
    assert entry.ip == "127.0.0.1"
    assert entry.seq == 0
    assert entry.prev_hash == ACCESS_GENESIS_HASH
    assert len(access.read_all()) == 1


def test_the_access_log_forms_a_hash_chain(tmp_path: Path) -> None:
    access = AccessLog(tmp_path / "access.jsonl")
    first = access.record(user_id="admin", action="login", target="session", result="success")
    second = access.record(user_id="admin", action="logout", target="session", result="success")

    assert second.prev_hash == first.hash
    assert access.verify() is True


def test_a_tampered_access_log_breaks_the_chain(tmp_path: Path) -> None:
    path = tmp_path / "access.jsonl"
    access = AccessLog(path)
    access.record(user_id="admin", action="login", target="session", result="success")
    access.record(user_id="admin", action="logout", target="session", result="success")

    lines = path.read_text(encoding="utf-8").splitlines()
    payload = json.loads(lines[0])
    payload["user_id"] = "someone else"
    lines[0] = json.dumps(payload)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    assert access.verify() is False


def test_conversation_store_redacts_and_addresses_content(tmp_path: Path) -> None:
    store = ConversationStore(tmp_path / "conversations")
    record = store.store(
        tenant_id="t1",
        role="coder",
        model="groq/x",
        prompt="use key sk-abcdefghijklmnopqrstuvwx please",
        response="ok",
        prompt_tokens=10,
        completion_tokens=2,
    )

    assert record.total_tokens == 12
    stored = store.text_for(record.prompt_hash)
    assert "sk-abcdefghijklmnopqrstuvwx" not in stored
    assert "[REDACTED]" in stored
    assert len(store.read_all()) == 1


def test_conversation_store_deduplicates_identical_texts(tmp_path: Path) -> None:
    store = ConversationStore(tmp_path / "conversations")
    first = store.store(tenant_id="t1", role="coder", model="m", prompt="same", response="r")
    second = store.store(tenant_id="t1", role="coder", model="m", prompt="same", response="r")
    assert first.prompt_hash == second.prompt_hash
    assert first.call_id != second.call_id
