"""API rate limiting middleware — sliding window per identity+bucket."""

from __future__ import annotations

import time
from collections import defaultdict, deque

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

# Paths excluded from rate limiting
_EXCLUDED_PATHS = {"/api/v1/health"}

# Per-endpoint RPM overrides (matched by prefix)
_ENDPOINT_LIMITS: dict[str, int] = {
    "/api/v1/auth/": 10,
    "/api/v1/runs/": 15,
    "/api/v1/scans/": 15,
    "/api/v1/engagements/": 15,
}


def _extract_identity(request: Request) -> str | None:
    """Rate-limit identity: the API key (required to reach the handler, verified
    downstream). The old version decoded the JWT with verify_signature=False and
    used its 'sub' — a caller could attach an arbitrary UNSIGNED bearer token with
    a random sub on every request to get a fresh bucket, fully bypassing the
    per-identity RPM cap on expensive endpoints. Never key throttling on an
    unverified, attacker-chosen value."""
    api_key = request.headers.get("x-api-key") or request.headers.get("api-key")
    if api_key:
        import hashlib

        return "k:" + hashlib.sha256(api_key.encode()).hexdigest()[:16]
    return None


def _get_bucket(path: str) -> tuple[str, int | None]:
    """Return (bucket_name, limit_override) for the given path."""
    for prefix, limit in _ENDPOINT_LIMITS.items():
        if path.startswith(prefix):
            return prefix, limit
    return "default", None


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Sliding-window rate limiter per (identity, bucket)."""

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

        identity = _extract_identity(request) or self._get_client_ip(request)
        bucket, limit_override = _get_bucket(request.url.path)
        effective_limit = limit_override if limit_override is not None else self._rpm

        key = f"{identity}:{bucket}"
        now = time.monotonic()
        window_start = now - 60.0

        dq = self._requests[key]

        # Prune old entries
        while dq and dq[0] < window_start:
            dq.popleft()

        # Clean up empty deques to prevent memory leak
        if not dq:
            del self._requests[key]
            dq = self._requests[key]  # re-create via defaultdict

        if len(dq) >= effective_limit:
            retry_after = int(dq[0] - window_start + 1)
            return JSONResponse(
                status_code=429,
                content={"detail": "Too many requests"},
                headers={"Retry-After": str(max(retry_after, 1))},
            )

        dq.append(now)

        response = await call_next(request)
        response.headers["X-RateLimit-Limit"] = str(effective_limit)
        response.headers["X-RateLimit-Remaining"] = str(max(0, effective_limit - len(dq)))
        return response
