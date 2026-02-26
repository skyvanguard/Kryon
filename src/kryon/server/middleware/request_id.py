"""Request ID middleware — generates a unique ID per request for tracing."""

from __future__ import annotations

import contextvars
import uuid

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import Response

request_id_var: contextvars.ContextVar[str] = contextvars.ContextVar("request_id", default="")


def get_request_id() -> str:
    """Get the current request ID from context."""
    return request_id_var.get()


class RequestIdMiddleware(BaseHTTPMiddleware):
    """Generates an X-Request-Id header for every request."""

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        rid = request.headers.get("X-Request-Id") or uuid.uuid4().hex[:8]
        request_id_var.set(rid)
        response = await call_next(request)
        response.headers["X-Request-Id"] = rid
        return response
