"""Tenant resolution middleware — resolves tenant from JWT, header, or subdomain."""

from __future__ import annotations

import logging

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import Response

from kryon.tenancy import set_tenant

logger = logging.getLogger(__name__)

# Default tenant for single-tenant backwards compatibility
_DEFAULT_TENANT = {"id": "default", "name": "Default", "slug": "default", "tier": "enterprise"}


class TenantResolutionMiddleware(BaseHTTPMiddleware):
    """Resolves the current tenant from request context."""

    def __init__(self, app, enabled: bool = False):
        super().__init__(app)
        self._enabled = enabled

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        if not self._enabled:
            set_tenant(_DEFAULT_TENANT)
            return await call_next(request)

        tenant = None

        # 1. Try JWT claim 'tenant_id'
        tenant_id = getattr(request.state, "tenant_id", None)
        if tenant_id:
            tenant = self._resolve_from_id(tenant_id)

        # 2. Try X-Tenant-ID header
        if not tenant:
            header_id = request.headers.get("X-Tenant-ID")
            if header_id:
                tenant = self._resolve_from_id(header_id)

        # 3. Try subdomain
        if not tenant:
            host = request.headers.get("host", "")
            subdomain = self._extract_subdomain(host)
            if subdomain and subdomain not in ("www", "api", "localhost"):
                tenant = self._resolve_from_slug(subdomain)

        # 4. Default tenant
        if not tenant:
            tenant = _DEFAULT_TENANT

        set_tenant(tenant)
        return await call_next(request)

    def _resolve_from_id(self, tenant_id: str) -> dict | None:
        try:
            from kryon.server.deps import get_store

            return get_store().get_tenant(tenant_id)
        except Exception:
            return None

    def _resolve_from_slug(self, slug: str) -> dict | None:
        try:
            from kryon.server.deps import get_store

            return get_store().get_tenant_by_slug(slug)
        except Exception:
            return None

    def _extract_subdomain(self, host: str) -> str | None:
        # Remove port
        host = host.split(":")[0]
        parts = host.split(".")
        if len(parts) >= 3:
            return parts[0]
        return None
