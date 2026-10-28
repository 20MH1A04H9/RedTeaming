"""RateLimiter: wraps a primary backend with memory fallback and a tiny circuit breaker."""
from __future__ import annotations

import logging
import time

from .algorithms import Result

log = logging.getLogger("viswa_ratelimiter")


class RateLimiter:
    def __init__(self, primary, fallback=None, fail_open: bool = False, cooldown: float = 5.0):
        """
        primary   - e.g. RedisTokenBucket(...)
        fallback  - e.g. TokenBucket(...) used when primary errors (per-process limits)
        fail_open - if no fallback and primary is down: True = allow, False = deny
        cooldown  - seconds to skip the primary after a failure (circuit breaker)
        """
        self.primary, self.fallback = primary, fallback
        self.fail_open, self.cooldown = fail_open, cooldown
        self._open_until = 0.0

    async def check(self, key: str, cost: int = 1) -> Result:
        if time.monotonic() >= self._open_until:
            try:
                return await self.primary.check(key, cost)
            except Exception as exc:  # backend down / timeout
                log.warning("rate limit backend failed (%s); using fallback", exc)
                self._open_until = time.monotonic() + self.cooldown
        if self.fallback is not None:
            return await self.fallback.check(key, cost)
        if self.fail_open:
            return Result(True, 0, 0)
        return Result(False, 0, 0, self.cooldown)
