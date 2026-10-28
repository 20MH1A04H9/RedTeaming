"""Pure-ASGI middleware: works with FastAPI, Starlette, or any ASGI app."""
from __future__ import annotations

import json
import math


def client_ip(scope, trust_proxy: bool = False) -> str:
    if trust_proxy:
        # Only enable behind a proxy you control; otherwise clients can spoof this header.
        for name, value in scope.get("headers", []):
            if name == b"x-forwarded-for":
                return value.decode().split(",")[0].strip()
    client = scope.get("client")
    return client[0] if client else "unknown"


class RateLimitMiddleware:
    def __init__(self, app, limiter, key_func=None, trust_proxy=False, exempt_paths=("/health",)):
        self.app, self.limiter = app, limiter
        self.key_func = key_func or (lambda scope: client_ip(scope, trust_proxy))
        self.exempt = tuple(exempt_paths)

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or scope["path"] in self.exempt:
            return await self.app(scope, receive, send)

        res = await self.limiter.check(self.key_func(scope))
        headers = [
            (b"x-ratelimit-limit", str(res.limit).encode()),
            (b"x-ratelimit-remaining", str(res.remaining).encode()),
        ]

        if not res.allowed:
            retry = max(1, math.ceil(res.retry_after))
            body = json.dumps({"detail": "Too Many Requests", "retry_after": retry}).encode()
            await send({"type": "http.response.start", "status": 429, "headers": headers + [
                (b"retry-after", str(retry).encode()),
                (b"content-type", b"application/json"),
                (b"content-length", str(len(body)).encode()),
            ]})
            return await send({"type": "http.response.body", "body": body})

        async def send_with_headers(message):
            if message["type"] == "http.response.start":
                message = {**message, "headers": list(message.get("headers", [])) + headers}
            await send(message)

        await self.app(scope, receive, send_with_headers)
