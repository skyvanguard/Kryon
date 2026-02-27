"""API rate limiting middleware — sliding window per IP."""

from __future__ import annotations

import time
from collections import defaultdict, deque

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

# Paths excluded from rate limiting
_EXCLUDED_PATHS = {"/api/v1/health"}


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Sliding-window rate limiter per client IP."""

    def __init__(self, app, rpm: int = 60, trusted_proxies: set[str] | None = None):
        super().__init__(app)
        self._rpm = rpm
        self._requests: dict[str, deque[float]] = defaultdict(deque)
        self._trusted_proxies = trusted_proxies or {"127.0.0.1", "::1"}

    def _get_client_ip(self, request: Request) -> str:
        client_host = request.client.host if request.client else "unknown"
        # Only trust X-Forwarded-For if request comes from a trusted proxy
        if client_host in self._trusted_proxies:
            forwarded = request.headers.get("X-Forwarded-For")
            if forwarded:
                return forwarded.split(",")[0].strip()
        return client_host

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        if request.url.path in _EXCLUDED_PATHS:
            return await call_next(request)

        ip = self._get_client_ip(request)
        now = time.monotonic()
        window_start = now - 60.0

        dq = self._requests[ip]

        # Prune old entries
        while dq and dq[0] < window_start:
            dq.popleft()

        if len(dq) >= self._rpm:
            retry_after = int(dq[0] - window_start + 1)
            return JSONResponse(
                status_code=429,
                content={"detail": "Too many requests"},
                headers={"Retry-After": str(max(retry_after, 1))},
            )

        dq.append(now)

        response = await call_next(request)
        response.headers["X-RateLimit-Limit"] = str(self._rpm)
        response.headers["X-RateLimit-Remaining"] = str(max(0, self._rpm - len(dq)))
        return response
