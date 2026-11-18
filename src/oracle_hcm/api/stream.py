"""The live view of the audit log.

The stream tails the audit log and hands every new event to the subscribers
of its tenant. A subscriber of one tenant never sees an event of another
tenant.

A subscriber may ask for the events it has not seen yet, with the sequence
number it stopped at. The events that were read in the meantime are held in a
buffer, so a client that reconnects does not lose the events of the gap.
"""

from __future__ import annotations

import asyncio
import logging
from collections import deque
from collections.abc import AsyncGenerator
from dataclasses import dataclass, field

from oracle_hcm.log.eventlog import EventLog
from oracle_hcm.schemas.events import AuditEvent

__all__ = ["BUFFER_SIZE", "EventStream", "Subscriber"]

_LOGGER = logging.getLogger(__name__)

BUFFER_SIZE = 1000
"""How many events the stream keeps for a client that reconnects."""


@dataclass
class Subscriber:
    """One consumer of the stream."""

    tenant_id: str
    last_seq: int = 0
    queue: asyncio.Queue[AuditEvent] = field(default_factory=asyncio.Queue)


class EventStream:
    """Tails the audit log and publishes its new events."""

    def __init__(
        self,
        event_log: EventLog,
        *,
        poll_interval: float = 0.2,
        buffer_size: int = BUFFER_SIZE,
    ) -> None:
        self._event_log = event_log
        self._poll_interval = poll_interval
        self._buffer: deque[AuditEvent] = deque(maxlen=buffer_size)
        self._offset = 0
        self._subscribers: dict[int, Subscriber] = {}
        self._task: asyncio.Task[None] | None = None

    @property
    def path(self) -> object:
        """The file the stream tails."""
        return self._event_log.path

    async def start(self) -> None:
        """Start tailing, from the end of the log."""
        path = self._event_log.path
        if path.is_file():
            self._offset = path.stat().st_size
        if self._task is None:
            self._task = asyncio.create_task(self._tail())

    async def stop(self) -> None:
        """Stop tailing."""
        if self._task is not None:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
            except Exception:
                _LOGGER.exception("the event stream stopped on an error")
            self._task = None

    def _read_new(self) -> list[AuditEvent]:
        """The events that were appended since the last read."""
        path = self._event_log.path
        if not path.is_file():
            return []
        with path.open("rb") as handle:
            handle.seek(self._offset)
            data = handle.read()
        if not data:
            return []
        text = data.decode("utf-8", errors="replace")
        end = text.rfind("\n")
        if end < 0:
            return []
        self._offset += len(text[: end + 1].encode("utf-8"))
        events: list[AuditEvent] = []
        for line in text[: end + 1].splitlines():
            if not line.strip():
                continue
            try:
                events.append(AuditEvent.model_validate_json(line))
            except ValueError:
                continue
        return events

    def poll(self) -> list[AuditEvent]:
        """Read the new events and publish them, right now."""
        events = self._read_new()
        for event in events:
            self._buffer.append(event)
            self._publish(event)
        return events

    def _publish(self, event: AuditEvent) -> None:
        """Hand an event to the subscribers of its tenant."""
        for subscriber in list(self._subscribers.values()):
            if subscriber.tenant_id != event.tenant_id:
                continue
            try:
                subscriber.queue.put_nowait(event)
            except asyncio.QueueFull:
                continue

    async def _tail(self) -> None:
        while True:
            await asyncio.sleep(self._poll_interval)
            try:
                self.poll()
            except OSError:
                continue

    def head_seq(self) -> int:
        """The sequence number of the last event the stream has read."""
        return self._buffer[-1].seq if self._buffer else 0

    async def subscribe(
        self,
        tenant_id: str,
        *,
        since_seq: int | None = None,
        idle_seconds: float | None = None,
    ) -> AsyncGenerator[AuditEvent | None, None]:
        """The events of one tenant, as they happen.

        With ``since_seq`` the events from that sequence number on are
        delivered first, so a client that reconnects misses nothing. Without
        it only the events that happen after the subscription are delivered.
        With an idle delay the stream yields ``None`` when no event arrived in
        time, which lets the caller send a keep-alive.
        """
        subscriber = Subscriber(
            tenant_id=tenant_id,
            last_seq=since_seq - 1 if since_seq is not None else self.head_seq(),
        )
        key = id(subscriber)
        self._subscribers[key] = subscriber
        try:
            for event in list(self._buffer):
                if event.seq > subscriber.last_seq and event.tenant_id == tenant_id:
                    subscriber.last_seq = event.seq
                    yield event
            while True:
                if idle_seconds is None:
                    event = await subscriber.queue.get()
                else:
                    try:
                        async with asyncio.timeout(idle_seconds):
                            event = await subscriber.queue.get()
                    except TimeoutError:
                        yield None
                        continue
                if event.seq <= subscriber.last_seq:
                    continue
                subscriber.last_seq = event.seq
                yield event
        finally:
            self._subscribers.pop(key, None)
