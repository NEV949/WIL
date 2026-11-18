"""Bus envelope security and backends."""

from __future__ import annotations

import pytest

from oracle_hcm.bus.memory import InMemoryBus, new_envelope
from oracle_hcm.bus.redis_streams import RedisStreamsBus, create_redis_client
from oracle_hcm.schemas.artifacts import RequirementSpec
from oracle_hcm.signing.signer import Signer, Verifier

REQUIREMENTS_PAYLOAD: dict[str, object] = {
    "requirement_id": "R-1",
    "title": "Add overtime",
    "description": "Calculate overtime for monthly staff",
    "acceptance_criteria": ["Overtime is paid at 1.5x"],
}


def _bus(signer: Signer, verifier: Verifier) -> InMemoryBus:
    bus = InMemoryBus(signer=signer, verifier=verifier)
    bus.register_schema("RequirementSpec", RequirementSpec)
    return bus


async def test_round_trip_is_verified(signer: Signer, verifier: Verifier) -> None:
    bus = _bus(signer, verifier)
    envelope = new_envelope(type_name="RequirementSpec", payload=REQUIREMENTS_PAYLOAD)
    await bus.publish(envelope)

    received = await bus.poll(consumer="orchestrator")
    assert len(received) == 1
    assert received[0].id == envelope.id
    assert received[0].signature


async def test_tampered_payload_is_rejected(signer: Signer, verifier: Verifier) -> None:
    bus = _bus(signer, verifier)
    envelope = new_envelope(type_name="RequirementSpec", payload=REQUIREMENTS_PAYLOAD)
    await bus.publish(envelope)

    queue = bus._queue  # the raw queue, to inject a tampered envelope
    signed = queue.get_nowait()
    signed.payload["title"] = "tampered"
    await queue.put(signed)

    received = await bus.poll(consumer="orchestrator")
    assert received == []
    assert len(bus.rejected) == 1


async def test_other_tenant_is_rejected(signer: Signer, verifier: Verifier) -> None:
    bus = _bus(signer, verifier)
    await bus.publish(new_envelope(type_name="RequirementSpec", payload=REQUIREMENTS_PAYLOAD))

    received = await bus.poll(consumer="orchestrator", tenant_id="other-tenant")
    assert received == []
    assert len(bus.rejected) == 1


async def test_payload_must_match_the_registered_schema(
    signer: Signer, verifier: Verifier
) -> None:
    bus = _bus(signer, verifier)
    await bus.publish(new_envelope(type_name="RequirementSpec", payload={"title": "no id"}))

    received = await bus.poll(consumer="orchestrator")
    assert received == []
    assert len(bus.rejected) == 1


async def test_unsigned_envelope_is_rejected(signer: Signer, verifier: Verifier) -> None:
    bus = _bus(signer, verifier)
    await bus.publish_raw(new_envelope(type_name="RequirementSpec", payload=REQUIREMENTS_PAYLOAD))

    received = await bus.poll(consumer="orchestrator")
    assert received == []
    assert len(bus.rejected) == 1


async def test_envelope_uses_json_ld_keys(signer: Signer, verifier: Verifier) -> None:
    bus = _bus(signer, verifier)
    envelope = new_envelope(type_name="RequirementSpec", payload=REQUIREMENTS_PAYLOAD)
    signed = bus.sign_envelope(envelope)
    dumped = signed.model_dump(mode="json", by_alias=True)
    assert dumped["@context"] == signed.context
    assert dumped["@type"] == "RequirementSpec"
    assert "signature" in dumped


async def _redis_reachable() -> bool:
    try:
        client = create_redis_client()
        await client.ping()
        await client.aclose()
    except Exception:
        return False
    return True

@pytest.mark.integration
async def test_redis_streams_round_trip(
    signer: Signer,
    verifier: Verifier,
    redis_password: str | None,
) -> None:
    if not await _redis_reachable():
        pytest.skip("redis is not reachable on 127.0.0.1:6379")
    client = create_redis_client()
    bus = RedisStreamsBus(
        client,
        signer=signer,
        verifier=verifier,
        stream="oracle.bus.test",
        group="test-group",
    )
    bus.register_schema("RequirementSpec", RequirementSpec)

    envelope = new_envelope(type_name="RequirementSpec", payload=REQUIREMENTS_PAYLOAD)
    message_id = await bus.publish(envelope)
    assert message_id

    received = await bus.poll(consumer="consumer-1", tenant_id="default", count=10, block_ms=200)
    assert [item.id for item in received] == [envelope.id]
    await client.delete("oracle.bus.test")
    await client.aclose()
