"""Redis-backed algorithms. Atomic via Lua so multiple app instances share one view."""
from __future__ import annotations

import os

from .algorithms import Result

_TOKEN_BUCKET_LUA = """
local cap  = tonumber(ARGV[1])
local rate = tonumber(ARGV[2])
local cost = tonumber(ARGV[3])
local t = redis.call('TIME')
local now = tonumber(t[1]) + tonumber(t[2]) / 1000000
local d = redis.call('HMGET', KEYS[1], 'tokens', 'ts')
local tokens = tonumber(d[1])
local ts = tonumber(d[2])
if tokens == nil then tokens = cap; ts = now end
tokens = math.min(cap, tokens + (now - ts) * rate)
local allowed = 0
local retry = 0
if tokens >= cost then tokens = tokens - cost; allowed = 1
else retry = (cost - tokens) / rate end
redis.call('HSET', KEYS[1], 'tokens', tokens, 'ts', now)
redis.call('PEXPIRE', KEYS[1], math.ceil(cap / rate * 2000))
return {allowed, tostring(tokens), tostring(retry)}
"""

_SLIDING_WINDOW_LUA = """
local limit  = tonumber(ARGV[1])
local window = tonumber(ARGV[2])
local cost   = tonumber(ARGV[3])
local uid    = ARGV[4]
local t = redis.call('TIME')
local now = tonumber(t[1]) + tonumber(t[2]) / 1000000
redis.call('ZREMRANGEBYSCORE', KEYS[1], '-inf', now - window)
local count = redis.call('ZCARD', KEYS[1])
if count + cost <= limit then
  for i = 1, cost do redis.call('ZADD', KEYS[1], now, uid .. ':' .. i) end
  redis.call('PEXPIRE', KEYS[1], math.ceil(window * 1000))
  return {1, tostring(limit - count - cost), '0'}
end
local need = math.min(count + cost - limit, count)
local oldest = redis.call('ZRANGE', KEYS[1], need - 1, need - 1, 'WITHSCORES')
local retry = window
if oldest[2] then retry = tonumber(oldest[2]) + window - now end
return {0, tostring(math.max(0, limit - count)), tostring(retry)}
"""


class RedisTokenBucket:
    def __init__(self, client, capacity: int, refill_per_sec: float, prefix: str = "viswa:tb:"):
        self.capacity, self.rate, self.prefix = capacity, refill_per_sec, prefix
        self._script = client.register_script(_TOKEN_BUCKET_LUA)

    async def check(self, key: str, cost: int = 1) -> Result:
        allowed, tokens, retry = await self._script(
            keys=[self.prefix + key], args=[self.capacity, self.rate, cost]
        )
        return Result(bool(allowed), self.capacity, int(float(tokens)), float(retry))


class RedisSlidingWindow:
    def __init__(self, client, limit: int, window: float, prefix: str = "viswa:sw:"):
        self.limit, self.window, self.prefix = limit, window, prefix
        self._script = client.register_script(_SLIDING_WINDOW_LUA)

    async def check(self, key: str, cost: int = 1) -> Result:
        uid = os.urandom(8).hex()
        allowed, remaining, retry = await self._script(
            keys=[self.prefix + key], args=[self.limit, self.window, cost, uid]
        )
        return Result(bool(allowed), self.limit, int(float(remaining)), float(retry))
