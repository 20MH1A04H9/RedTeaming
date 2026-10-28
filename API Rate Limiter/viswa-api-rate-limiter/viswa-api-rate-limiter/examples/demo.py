"""Run: uvicorn examples.demo:app   (needs: pip install fastapi uvicorn redis)"""
import os

from fastapi import FastAPI

from viswa_ratelimiter import RateLimiter, RateLimitMiddleware, TokenBucket

fallback = TokenBucket(capacity=10, refill_per_sec=1)
primary = fallback
if os.getenv("REDIS_URL"):
    import redis.asyncio as redis
    from viswa_ratelimiter.redis_store import RedisTokenBucket
    primary = RedisTokenBucket(redis.from_url(os.environ["REDIS_URL"]), 10, 1)

app = FastAPI()
app.add_middleware(RateLimitMiddleware, limiter=RateLimiter(primary, fallback=fallback))


@app.get("/")
async def root():
    return {"hello": "viswa"}


@app.get("/health")
async def health():
    return {"ok": True}
