"""API key authentication — original auth mechanism."""

import os
import secrets

from fastapi import HTTPException, Security
from fastapi.security import APIKeyHeader

_api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)

# Mutable list populated at startup from ServerConfig
_valid_keys: list[str] = []

# Explicit opt-in required to run without auth (KRYON_ALLOW_UNAUTHENTICATED=true)
_allow_unauthenticated: bool = False


def configure_auth(api_keys: list[str]) -> None:
    """Set the valid API keys.

    If no keys are provided, authentication is REQUIRED unless
    KRYON_ALLOW_UNAUTHENTICATED=true is explicitly set.
    """
    global _allow_unauthenticated
    _valid_keys.clear()
    _valid_keys.extend(api_keys)
    _allow_unauthenticated = os.getenv("KRYON_ALLOW_UNAUTHENTICATED", "").lower() in ("true", "1", "yes")


def _constant_time_key_check(key: str) -> bool:
    """Check if key matches any valid key using constant-time comparison."""
    return any(secrets.compare_digest(key, valid_key) for valid_key in _valid_keys)


async def require_api_key(
    key: str | None = Security(_api_key_header),
) -> str | None:
    """FastAPI dependency that validates the API key.

    Blocks all requests when no keys are configured UNLESS
    KRYON_ALLOW_UNAUTHENTICATED=true is explicitly set.
    """
    if not _valid_keys:
        if _allow_unauthenticated:
            return None
        raise HTTPException(
            status_code=401,
            detail="Authentication required. Set KRYON_API_KEY or KRYON_ALLOW_UNAUTHENTICATED=true for dev mode.",
        )
    if key is None or not _constant_time_key_check(key):
        raise HTTPException(status_code=401, detail="Invalid or missing API key")
    return key
