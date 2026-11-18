"""Runs of the orchestrator, started by the gateway.

A run takes a long time: the agents call models, the sandbox executes the
code. The gateway therefore starts the run in the background and answers the
caller at once. The run writes its state to disk, so a suspended run can be
resumed later, even after a restart of the gateway.

The run happens in a worker thread with its own event loop, so a slow model
call never blocks the gateway.
"""

from __future__ import annotations

import asyncio
import uuid
from collections.abc import Callable, Coroutine
from typing import Any

from oracle_hcm.log.eventlog import EventLog
from oracle_hcm.services.orchestrator import Orchestrator

__all__ = ["RunFactory", "RunManager"]

RunFactory = Callable[[], Coroutine[Any, Any, Any]]


class RunManager:
    """Starts and resumes the runs of the orchestrator in the background."""

    def __init__(self, *, orchestrator: Orchestrator, event_log: EventLog) -> None:
        self._orchestrator = orchestrator
        self._event_log = event_log
        self._tasks: dict[str, asyncio.Task[None]] = {}

    def new_task_id(self) -> str:
        """An identifier for a new run."""
        return uuid.uuid4().hex[:12]

    async def start(self, *, task_id: str, request: str, tenant_id: str) -> None:
        """Start a run in the background."""
        self._spawn(
            task_id,
            lambda: self._orchestrator.run(request, tenant_id=tenant_id, run_id=task_id),
        )

    async def resume(self, *, task_id: str) -> None:
        """Resume a suspended run in the background."""
        self._spawn(task_id, lambda: self._orchestrator.resume(task_id))

    def _spawn(self, task_id: str, factory: RunFactory) -> None:
        """Run the coroutine in a worker thread, so the gateway stays free."""
        previous = self._tasks.pop(task_id, None)
        if previous is not None and not previous.done():
            previous.cancel()
        self._tasks[task_id] = asyncio.create_task(self._run(factory, task_id))

    async def _run(self, factory: RunFactory, task_id: str) -> None:
        """Wait for the run, and record a failure that escapes it."""
        try:
            await asyncio.to_thread(self._drive, factory)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            self._event_log.append(
                tenant_id=self._tenant_of(task_id),
                actor="orchestrator",
                action="run_failed",
                payload={"run_id": task_id, "failure": str(exc)},
            )

    def _drive(self, factory: RunFactory) -> None:
        """Run the coroutine in its own event loop."""
        asyncio.run(factory())

    def _tenant_of(self, task_id: str) -> str:
        """The tenant of a run, taken from the events of the run."""
        for event in reversed(self._event_log.read_all()):
            if event.payload.get("run_id") == task_id:
                return event.tenant_id
        return "default"

    async def shutdown(self) -> None:
        """Stop every background run."""
        for task in list(self._tasks.values()):
            task.cancel()
        self._tasks.clear()

    def active(self) -> list[str]:
        """The runs that are still going."""
        return [key for key, task in self._tasks.items() if not task.done()]
