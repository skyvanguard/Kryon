"""Security headers middleware — adds defensive HTTP headers to all responses."""

from __future__ import annotations

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import Response

_SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
}


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Adds security headers to every response."""

    def __init__(self, app, https_enabled: bool = False):
        super().__init__(app)
        self._https_enabled = https_enabled

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        response = await call_next(request)
        for header, value in _SECURITY_HEADERS.items():
            response.headers[header] = value
        if self._https_enabled:
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        return response
