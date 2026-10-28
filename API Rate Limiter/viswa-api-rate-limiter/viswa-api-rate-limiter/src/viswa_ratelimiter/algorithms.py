"""In-memory rate limiting algorithms (token bucket, sliding window, fixed window)."""
from __future__ import annotations

import threading
import time
from collections import deque
from dataclasses import dataclass
from typing import Callable

Clock = Callable[[], float]


@dataclass(frozen=True)
class Result:
    allowed: bool
    limit: int
    remaining: int
    retry_after: float = 0.0  # seconds until the request could succeed


class _MemoryBase:
    _SWEEP_EVERY = 1000

    def __init__(self, clock: Clock = time.monotonic) -> None:
        self._clock = clock
        self._lock = threading.Lock()
        self._calls = 0

    def _maybe_sweep(self, now: float) -> None:
        self._calls += 1
        if self._calls % self._SWEEP_EVERY == 0:
            self._sweep(now)

    def _sweep(self, now: float) -> None:  # pragma: no cover - overridden
        raise NotImplementedError


class TokenBucket(_MemoryBase):
    """Allows bursts up to `capacity`, refilling at `refill_per_sec` tokens/second."""

    def __init__(self, capacity: int, refill_per_sec: float, clock: Clock = time.monotonic):
        super().__init__(clock)
        if capacity < 1 or refill_per_sec <= 0:
            raise ValueError("capacity must be >= 1 and refill_per_sec > 0")
        self.capacity = capacity
        self.rate = refill_per_sec
        self._state: dict[str, tuple[float, float]] = {}

    async def check(self, key: str, cost: int = 1) -> Result:
        with self._lock:
            now = self._clock()
            self._maybe_sweep(now)
            tokens, last = self._state.get(key, (float(self.capacity), now))
            tokens = min(self.capacity, tokens + (now - last) * self.rate)
            if tokens >= cost:
                tokens -= cost
                self._state[key] = (tokens, now)
                return Result(True, self.capacity, int(tokens))
            self._state[key] = (tokens, now)
            return Result(False, self.capacity, int(tokens), (cost - tokens) / self.rate)

    def _sweep(self, now: float) -> None:
        full_after = self.capacity / self.rate
        self._state = {k: v for k, v in self._state.items() if now - v[1] < full_after}


class SlidingWindow(_MemoryBase):
    """Exact sliding-window log: at most `limit` requests in any `window` seconds."""

    def __init__(self, limit: int, window: float, clock: Clock = time.monotonic):
        super().__init__(clock)
        if limit < 1 or window <= 0:
            raise ValueError("limit must be >= 1 and window > 0")
        self.limit = limit
        self.window = window
        self._hits: dict[str, deque[float]] = {}

    async def check(self, key: str, cost: int = 1) -> Result:
        with self._lock:
            now = self._clock()
            self._maybe_sweep(now)
            q = self._hits.setdefault(key, deque())
            while q and now - q[0] >= self.window:
                q.popleft()
            if len(q) + cost <= self.limit:
                q.extend([now] * cost)
                return Result(True, self.limit, self.limit - len(q))
            need = len(q) + cost - self.limit  # oldest entries that must expire
            retry = q[min(need, len(q)) - 1] + self.window - now if q else self.window
            return Result(False, self.limit, max(0, self.limit - len(q)), max(retry, 0.0))

    def _sweep(self, now: float) -> None:
        self._hits = {k: q for k, q in self._hits.items() if q and now - q[-1] < self.window}


class FixedWindow(_MemoryBase):
    """Simple counter reset every `window` seconds. Cheapest, but allows boundary bursts."""

    def __init__(self, limit: int, window: float, clock: Clock = time.monotonic):
        super().__init__(clock)
        if limit < 1 or window <= 0:
            raise ValueError("limit must be >= 1 and window > 0")
        self.limit = limit
        self.window = window
        self._state: dict[str, tuple[int, int]] = {}  # key -> (window_id, count)

    async def check(self, key: str, cost: int = 1) -> Result:
        with self._lock:
            now = self._clock()
            self._maybe_sweep(now)
            wid = int(now // self.window)
            cur_id, count = self._state.get(key, (wid, 0))
            if cur_id != wid:
                count = 0
            if count + cost <= self.limit:
                count += cost
                self._state[key] = (wid, count)
                return Result(True, self.limit, self.limit - count)
            self._state[key] = (wid, count)
            return Result(False, self.limit, max(0, self.limit - count), (wid + 1) * self.window - now)

    def _sweep(self, now: float) -> None:
        wid = int(now // self.window)
        self._state = {k: v for k, v in self._state.items() if v[0] == wid}
