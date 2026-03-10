"""Global error handler — catches unhandled exceptions and returns safe responses."""

from __future__ import annotations

import os

from fastapi import Request
from fastapi.responses import JSONResponse

from kryon.server.logging_config import get_logger
from kryon.server.middleware.request_id import get_request_id

logger = get_logger(__name__)


async def global_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    """Catch-all handler: logs full traceback, returns safe response to client."""
    rid = get_request_id()
    logger.error("Unhandled exception on %s %s", request.method, request.url.path, exc_info=exc)

    body: dict = {"detail": "Internal server error", "request_id": rid}

    # In debug mode, log error type for correlation (traceback stays in server logs only)
    debug = os.environ.get("KRYON_DEBUG", "0")
    if debug.lower() in ("1", "true", "yes"):
        body["error_type"] = type(exc).__name__

    return JSONResponse(status_code=500, content=body)
