import asyncio
import unittest

from viswa_ratelimiter import (FixedWindow, RateLimiter, RateLimitMiddleware,
                               SlidingWindow, TokenBucket)


class Clock:
    def __init__(self): self.t = 1000.0
    def __call__(self): return self.t


def run(c): return asyncio.run(c)


class AlgoTests(unittest.TestCase):
    def test_token_bucket_burst_and_refill(self):
        clk = Clock(); tb = TokenBucket(3, 1.0, clk)
        self.assertTrue(all(run(tb.check("a")).allowed for _ in range(3)))
        r = run(tb.check("a"))
        self.assertFalse(r.allowed); self.assertAlmostEqual(r.retry_after, 1.0)
        clk.t += 1.0
        self.assertTrue(run(tb.check("a")).allowed)
        self.assertTrue(run(tb.check("other")).allowed)  # keys are isolated

    def test_sliding_window(self):
        clk = Clock(); sw = SlidingWindow(2, 10, clk)
        run(sw.check("a")); clk.t += 4; run(sw.check("a"))
        r = run(sw.check("a"))
        self.assertFalse(r.allowed); self.assertAlmostEqual(r.retry_after, 6.0)
        clk.t += 6
        self.assertTrue(run(sw.check("a")).allowed)

    def test_fixed_window_resets(self):
        clk = Clock(); fw = FixedWindow(2, 10, clk)
        clk.t = 1000.0
        run(fw.check("a")); run(fw.check("a"))
        self.assertFalse(run(fw.check("a")).allowed)
        clk.t = 1010.0
        self.assertTrue(run(fw.check("a")).allowed)

    def test_cost(self):
        tb = TokenBucket(5, 1.0, Clock())
        self.assertTrue(run(tb.check("a", cost=5)).allowed)
        self.assertFalse(run(tb.check("a", cost=1)).allowed)


class Broken:
    async def check(self, key, cost=1): raise ConnectionError("redis down")


class FallbackTests(unittest.TestCase):
    def test_falls_back_to_memory(self):
        rl = RateLimiter(Broken(), fallback=TokenBucket(1, 0.1, Clock()))
        self.assertTrue(run(rl.check("a")).allowed)
        self.assertFalse(run(rl.check("a")).allowed)

    def test_fail_closed_and_open(self):
        self.assertFalse(run(RateLimiter(Broken()).check("a")).allowed)
        self.assertTrue(run(RateLimiter(Broken(), fail_open=True).check("a")).allowed)


class MiddlewareTests(unittest.TestCase):
    def test_429_after_limit(self):
        async def app(scope, receive, send):
            await send({"type": "http.response.start", "status": 200, "headers": []})
            await send({"type": "http.response.body", "body": b"ok"})

        mw = RateLimitMiddleware(app, TokenBucket(2, 0.01, Clock()))

        async def call(path="/x"):
            out = []
            async def send(m): out.append(m)
            async def receive(): return {"type": "http.request"}
            await mw({"type": "http", "path": path, "headers": [], "client": ("1.2.3.4", 1)}, receive, send)
            return out[0]

        async def go():
            return [(await call())["status"] for _ in range(3)], await call("/health")
        statuses, health = run(go())
        self.assertEqual(statuses, [200, 200, 429])
        self.assertEqual(health["status"], 200)  # exempt path


if __name__ == "__main__":
    unittest.main()
