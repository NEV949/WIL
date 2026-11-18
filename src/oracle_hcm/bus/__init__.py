"""Message bus."""

from __future__ import annotations

from oracle_hcm.bus.base import Bus
from oracle_hcm.bus.memory import InMemoryBus, new_envelope
from oracle_hcm.bus.redis_streams import RedisStreamsBus, create_redis_client

__all__ = [
    "Bus",
    "InMemoryBus",
    "RedisStreamsBus",
    "create_redis_client",
    "new_envelope",
]
