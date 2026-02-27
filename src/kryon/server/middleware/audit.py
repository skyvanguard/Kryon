"""Audit middleware — automatically logs mutating API requests."""

from __future__ import annotations

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import Response

# HTTP methods that mutate state
_AUDITED_METHODS = {"POST", "PUT", "DELETE", "PATCH"}


class AuditMiddleware(BaseHTTPMiddleware):
    """Logs POST/PUT/DELETE requests to the audit log."""

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        response = await call_next(request)

        if request.method in _AUDITED_METHODS and request.url.path.startswith("/api/"):
            try:
                from kryon.server.audit import log_action

                ip = request.headers.get("X-Forwarded-For", "").split(",")[0].strip()
                if not ip:
                    ip = request.client.host if request.client else "unknown"

                # Extract resource info from path (skip /api/v1/ prefix)
                parts = request.url.path.strip("/").split("/")
                # parts: ["api", "v1", "resource", "id"] or ["api", "resource", "id"]
                offset = 2 if len(parts) > 1 and parts[1].startswith("v") else 1
                resource_type = parts[offset] if len(parts) > offset else "unknown"
                resource_id = parts[offset + 1] if len(parts) > offset + 1 else None

                log_action(
                    action=f"{request.method} {request.url.path}",
                    resource_type=resource_type,
                    resource_id=resource_id,
                    ip_address=ip,
                    details={"status_code": response.status_code},
                )
                # Forward audit event to SIEM integrations
                try:
                    from kryon.integrations import get_integration_manager
                    from kryon.integrations.models import SIEMEvent

                    await get_integration_manager().forward_event(
                        SIEMEvent(
                            event_type="audit",
                            severity="info",
                            title=f"{request.method} {request.url.path}",
                            description=f"API {request.method} on {resource_type}",
                            metadata={"status_code": response.status_code, "resource_id": resource_id or ""},
                            user=ip,
                        )
                    )
                except Exception:
                    pass  # Never fail due to SIEM forwarding
            except Exception:
                pass  # Never fail a request due to audit logging

        return response
