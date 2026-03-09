"""JWT token creation and validation."""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

import jwt

# Module-level config set by configure_jwt()
_jwt_secret: str = ""
_access_ttl_minutes: int = 60
_refresh_ttl_days: int = 7
_algorithm: str = "HS256"
_jwt_issuer: str = "kryon"
_jwt_audience: str = "kryon-api"

# In-memory revoked token set (jti -> expiry timestamp)
_revoked_tokens: dict[str, float] = {}


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
        "jti": uuid.uuid4().hex,
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
        "jti": uuid.uuid4().hex,
        "iss": _jwt_issuer,
        "aud": _jwt_audience,
        "exp": now + timedelta(days=_refresh_ttl_days),
        "iat": now,
    }
    return jwt.encode(payload, _jwt_secret, algorithm=_algorithm)


def revoke_token(jti: str, exp: float) -> None:
    """Revoke a token by its jti claim."""
    _revoked_tokens[jti] = exp
    # Prune expired revocations to prevent unbounded growth
    now = datetime.now(timezone.utc).timestamp()
    expired = [k for k, v in _revoked_tokens.items() if v < now]
    for k in expired:
        _revoked_tokens.pop(k, None)


def is_token_revoked(jti: str) -> bool:
    """Check if a token has been revoked."""
    return jti in _revoked_tokens


def decode_token(token: str) -> dict:
    """Decode and validate a JWT token. Raises jwt.PyJWTError on failure."""
    payload = jwt.decode(
        token,
        _jwt_secret,
        algorithms=[_algorithm],
        issuer=_jwt_issuer,
        audience=_jwt_audience,
    )
    # Check revocation
    jti = payload.get("jti")
    if jti and is_token_revoked(jti):
        raise jwt.InvalidTokenError("Token has been revoked")
    return payload
