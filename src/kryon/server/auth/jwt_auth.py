"""JWT token creation and validation."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import jwt

# Module-level config set by configure_jwt()
_jwt_secret: str = ""
_access_ttl_minutes: int = 60
_refresh_ttl_days: int = 7
_algorithm: str = "HS256"
_jwt_issuer: str = "kryon"
_jwt_audience: str = "kryon-api"


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
    now = datetime.now(timezone.utc)
    payload = {
        "sub": user_id,
        "username": username,
        "role": role,
        "type": "access",
        "iss": _jwt_issuer,
        "aud": _jwt_audience,
        "exp": now + timedelta(minutes=_access_ttl_minutes),
        "iat": now,
    }
    return jwt.encode(payload, _jwt_secret, algorithm=_algorithm)


def create_refresh_token(user_id: str) -> str:
    """Create a long-lived refresh token."""
    now = datetime.now(timezone.utc)
    payload = {
        "sub": user_id,
        "type": "refresh",
        "iss": _jwt_issuer,
        "aud": _jwt_audience,
        "exp": now + timedelta(days=_refresh_ttl_days),
        "iat": now,
    }
    return jwt.encode(payload, _jwt_secret, algorithm=_algorithm)


def decode_token(token: str) -> dict:
    """Decode and validate a JWT token. Raises jwt.PyJWTError on failure."""
    return jwt.decode(
        token, _jwt_secret, algorithms=[_algorithm],
        issuer=_jwt_issuer, audience=_jwt_audience,
    )
