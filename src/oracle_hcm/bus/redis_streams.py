"""Redis Streams bus backend."""

from __future__ import annotations

import os
from collections.abc import Mapping
from typing import Any, cast
from urllib.parse import quote

from redis.asyncio import Redis
from redis.exceptions import ResponseError

from oracle_hcm.bus.base import Bus
from oracle_hcm.errors import EnvelopeVerificationError
from oracle_hcm.schemas.envelope import Envelope
from oracle_hcm.signing.signer import Signer, Verifier

__all__ = ["RedisStreamsBus", "create_redis_client", "redis_url_from_env"]

DEFAULT_REDIS_HOST = "127.0.0.1"
DEFAULT_REDIS_PORT = 6379
DEFAULT_REDIS_DB = 0


def redis_url_from_env(env: Mapping[str, str] | None = None) -> str:
    """Build the Redis URL from the environment.

    REDIS_URL wins when set. Otherwise REDIS_PASSWORD is used to build an
    authenticated URL. With neither variable set the local instance is assumed
    to run without a password.
    """
    source: Mapping[str, str] = os.environ if env is None else env
    explicit = source.get("REDIS_URL")
    if explicit:
        return explicit
    password = source.get("REDIS_PASSWORD")
    if password:
        return (
            f"redis://:{quote(password, safe='')}@{DEFAULT_REDIS_HOST}:"
            f"{DEFAULT_REDIS_PORT}/{DEFAULT_REDIS_DB}"
        )
    return f"redis://{DEFAULT_REDIS_HOST}:{DEFAULT_REDIS_PORT}/{DEFAULT_REDIS_DB}"


def create_redis_client(url: str | None = None) -> Redis:
    """Client configured for text payloads."""
    return Redis.from_url(url or redis_url_from_env(), decode_responses=True)


class RedisStreamsBus(Bus):
    """Bus backed by a Redis stream."""

    def __init__(
        self,
        redis: Redis,
        *,
        signer: Signer,
        verifier: Verifier,
        stream: str = "oracle.bus",
        group: str = "orchestrator",
    ) -> None:
        super().__init__(signer=signer, verifier=verifier)
        self._redis = redis
        self._stream = stream
        self._group = group
        self._group_ready = False
        self.rejected: list[Envelope] = []

    async def _ensure_group(self) -> None:
        if self._group_ready:
            return
        try:
            await self._redis.xgroup_create(self._stream, self._group, id="0", mkstream=True)
        except ResponseError as exc:
            if "BUSYGROUP" not in str(exc):
                raise
        self._group_ready = True

    async def publish(self, envelope: Envelope) -> str:
        signed = self.sign_envelope(envelope)
        await self._ensure_group()
        message_id = await self._redis.xadd(
            self._stream, {"envelope": signed.model_dump_json(by_alias=True)}
        )
        return str(message_id)

    async def poll(
        self,
        *,
        consumer: str,
        tenant_id: str | None = None,
        count: int = 10,
        block_ms: int = 1000,
    ) -> list[Envelope]:
        await self._ensure_group()
        raw_entries = await self._redis.xreadgroup(
            self._group,
            consumer,
            {self._stream: ">"},
            count=count,
            block=block_ms,
        )
        entries: list[Any] = cast("list[Any]", raw_entries)
        verified: list[Envelope] = []
        for _stream_name, messages in entries:
            for _message_id, fields in messages:
                raw = fields.get("envelope") if isinstance(fields, dict) else None
                if not isinstance(raw, str):
                    continue
                try:
                    envelope = Envelope.model_validate_json(raw)
                except ValueError:
                    continue
                try:
                    verified.append(self.verify_envelope(envelope, expected_tenant=tenant_id))
                except EnvelopeVerificationError:
                    self.rejected.append(envelope)
        return verified
