"""Rate and token accounting for model calls."""

from __future__ import annotations

import json
import threading
import time
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path

from oracle_hcm.errors import RateLimitError

__all__ = ["DailyTokenCounter", "RateLimiter"]


class RateLimiter:
    """Sliding-window limiter enforcing per-model rpm and tpm."""

    def __init__(self, window_seconds: float = 60.0) -> None:
        self._window = window_seconds
        self._calls: dict[str, list[float]] = {}
        self._tokens: dict[str, list[tuple[float, int]]] = {}
        self._lock = threading.Lock()

    @staticmethod
    def _prune_calls(entries: list[float], now: float, window: float) -> list[float]:
        cutoff = now - window
        return [timestamp for timestamp in entries if timestamp > cutoff]

    @staticmethod
    def _prune_tokens(
        entries: list[tuple[float, int]], now: float, window: float
    ) -> list[tuple[float, int]]:
        cutoff = now - window
        return [(timestamp, amount) for timestamp, amount in entries if timestamp > cutoff]

    def wait_time(
        self,
        model: str,
        *,
        rpm: int,
        tpm: int,
        tokens: int = 0,
        now: float | None = None,
    ) -> float:
        """Seconds the caller must wait before issuing a request."""
        moment = time.monotonic() if now is None else now
        with self._lock:
            calls = self._prune_calls(self._calls.get(model, []), moment, self._window)
            token_entries = self._prune_tokens(self._tokens.get(model, []), moment, self._window)
            self._calls[model] = calls
            self._tokens[model] = token_entries

            wait = 0.0
            if rpm > 0 and len(calls) >= rpm:
                wait = max(wait, calls[0] + self._window - moment)
            if tpm > 0 and token_entries:
                used = sum(amount for _timestamp, amount in token_entries)
                if used + tokens > tpm:
                    wait = max(wait, token_entries[0][0] + self._window - moment)
            return max(wait, 0.0)

    def record(self, model: str, *, tokens: int = 0, now: float | None = None) -> None:
        """Consume one request slot and its tokens."""
        moment = time.monotonic() if now is None else now
        with self._lock:
            self._calls.setdefault(model, []).append(moment)
            if tokens > 0:
                self._tokens.setdefault(model, []).append((moment, tokens))

    def record_tokens(self, model: str, tokens: int, now: float | None = None) -> None:
        """Consume tokens without consuming a request slot."""
        if tokens <= 0:
            return
        moment = time.monotonic() if now is None else now
        with self._lock:
            self._tokens.setdefault(model, []).append((moment, tokens))


class DailyTokenCounter:
    """Counts tokens per model per UTC day, persisted to disk."""

    def __init__(
        self,
        path: Path | None = None,
        *,
        daily_budget: int | None = None,
        day_fn: Callable[[], str] | None = None,
    ) -> None:
        self._path = path
        self._daily_budget = daily_budget
        self._day_fn = day_fn if day_fn is not None else _today
        self._data: dict[str, dict[str, int]] = {}
        self._lock = threading.Lock()
        if path is not None and path.is_file():
            self._data = json.loads(path.read_text(encoding="utf-8"))

    def _day(self) -> str:
        return self._day_fn()

    def _flush(self) -> None:
        if self._path is None:
            return
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._path.write_text(json.dumps(self._data, sort_keys=True, indent=2), encoding="utf-8")

    def add(self, model: str, tokens: int) -> int:
        """Add tokens for a model and return the day's total for that model."""
        with self._lock:
            day = self._data.setdefault(self._day(), {})
            day[model] = day.get(model, 0) + tokens
            self._flush()
            return day[model]

    def total(self, model: str | None = None) -> int:
        """Tokens used today, overall or for one model."""
        with self._lock:
            day = self._data.get(self._day(), {})
            if model is None:
                return sum(day.values())
            return day.get(model, 0)

    def check_budget(self, projected: int = 0) -> None:
        """Raise RateLimitError when the daily budget would be exceeded."""
        if self._daily_budget is None:
            return
        if self.total() + projected > self._daily_budget:
            raise RateLimitError(
                f"daily token budget of {self._daily_budget} exceeded "
                f"({self.total()} used, {projected} requested)"
            )


def _today() -> str:
    return datetime.now(UTC).date().isoformat()
