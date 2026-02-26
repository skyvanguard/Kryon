"""JWT token creation and validation."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import jwt

# Module-level config set by configure_jwt()
_jwt_secret: str = ""
_access_ttl_minutes: int = 60
_refresh_ttl_days: int = 7
_algorithm: str = "HS256"


def configure_jwt(secret: str, access_ttl_minutes: int = 60) -> None:
    """Configure JWT parameters. Called at server startup."""
    global _jwt_secret, _access_ttl_minutes
    _jwt_secret = secret
    _access_ttl_minutes = access_ttl_minutes


def is_jwt_configured() -> bool:
    """Check if JWT auth is configured."""
    return bool(_jwt_secret)


def create_access_token(user_id: str, username: str, role: str) -> str:
    """Create a short-lived access token."""
    payload = {
        "sub": user_id,
        "username": username,
        "role": role,
        "type": "access",
        "exp": datetime.now(timezone.utc) + timedelta(minutes=_access_ttl_minutes),
        "iat": datetime.now(timezone.utc),
    }
    return jwt.encode(payload, _jwt_secret, algorithm=_algorithm)


def create_refresh_token(user_id: str) -> str:
    """Create a long-lived refresh token."""
    payload = {
        "sub": user_id,
        "type": "refresh",
        "exp": datetime.now(timezone.utc) + timedelta(days=_refresh_ttl_days),
        "iat": datetime.now(timezone.utc),
    }
    return jwt.encode(payload, _jwt_secret, algorithm=_algorithm)


def decode_token(token: str) -> dict:
    """Decode and validate a JWT token. Raises jwt.PyJWTError on failure."""
    return jwt.decode(token, _jwt_secret, algorithms=[_algorithm])
