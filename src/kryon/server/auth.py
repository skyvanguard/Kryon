"""API key authentication."""

from fastapi import HTTPException, Security
from fastapi.security import APIKeyHeader

_api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)

# Mutable set populated at startup from ServerConfig
_valid_keys: set[str] = set()


def configure_auth(api_keys: list[str]) -> None:
    """Set the valid API keys. Empty list disables auth."""
    _valid_keys.clear()
    _valid_keys.update(api_keys)


async def require_api_key(
    key: str | None = Security(_api_key_header),
) -> str | None:
    """FastAPI dependency that validates the API key.

    If no keys are configured (dev mode), authentication is disabled.
    """
    if not _valid_keys:
        return None
    if key is None or key not in _valid_keys:
        raise HTTPException(status_code=401, detail="Invalid or missing API key")
    return key
