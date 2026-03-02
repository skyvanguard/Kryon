"""FastAPI authentication dependencies — JWT or API key fallback."""

from __future__ import annotations

from fastapi import Depends, HTTPException, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from kryon.server.auth.api_key import require_api_key
from kryon.server.auth.jwt_auth import decode_token, is_jwt_configured
from kryon.server.auth.models import User

_bearer_scheme = HTTPBearer(auto_error=False)


async def get_current_user(
    request: Request,
    credentials: HTTPAuthorizationCredentials | None = Depends(_bearer_scheme),
    api_key: str | None = Depends(require_api_key),
) -> User | None:
    """Resolve the current user from JWT bearer token or API key.

    - If JWT auth is configured and a Bearer token is present, validate it.
    - If only API key auth is active, return None (API key already validated).
    - If neither is configured (dev mode), return None.
    """
    if not is_jwt_configured():
        # JWT not configured — fall back to API key auth (already validated)
        return None

    if credentials is None:
        # No bearer token — check if API key passed
        if api_key is not None:
            return None
        raise HTTPException(status_code=401, detail="Authentication required")

    try:
        payload = decode_token(credentials.credentials)
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid or expired token")

    if payload.get("type") != "access":
        raise HTTPException(status_code=401, detail="Invalid token type")

    # Resolve user from store
    from kryon.server.deps import get_store

    store = get_store()
    user = store.get_user_by_id(payload["sub"])
    if user is None or not user.is_active:
        raise HTTPException(status_code=401, detail="User not found or inactive")

    return user


def require_role(*roles: str):
    """Dependency factory that checks the user has one of the specified roles."""

    async def _check(user: User | None = Depends(get_current_user)):
        if user is None:
            # No JWT auth active — allow (API key or dev mode)
            return None
        if user.role not in roles:
            raise HTTPException(status_code=403, detail="Insufficient permissions")
        return user

    return _check
