"""JWT token creation and validation."""

from __future__ import annotations

import logging
import sqlite3
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import jwt

logger = logging.getLogger(__name__)

# Module-level config set by configure_jwt()
_jwt_secret: str = ""
_access_ttl_minutes: int = 60
_refresh_ttl_days: int = 7
_algorithm: str = "HS256"
_jwt_issuer: str = "kryon"
_jwt_audience: str = "kryon-api"

# Minimum HMAC key length for HS256. NIST SP 800-117/800-175B recommends the key
# be at least as long as the hash output (32 bytes for SHA-256). A shorter secret
# weakens the signature; we fail loud at startup rather than accept it silently.
_MIN_SECRET_LEN: int = 32

# SQLite-backed revocation store (survives restarts)
_revocation_db: Path | None = None


def _get_revocation_db() -> Path:
    """Return path to revocation DB, creating table if needed."""
    global _revocation_db
    if _revocation_db is None:
        db_dir = Path.home() / ".kryon"
        db_dir.mkdir(parents=True, exist_ok=True)
        _revocation_db = db_dir / "revoked_tokens.db"
    conn = sqlite3.connect(str(_revocation_db))
    conn.execute(
        "CREATE TABLE IF NOT EXISTS revoked_tokens (jti TEXT PRIMARY KEY, exp REAL NOT NULL, revoked_at REAL NOT NULL)"
    )
    conn.commit()
    conn.close()
    return _revocation_db


def configure_jwt(secret: str, access_ttl_minutes: int = 60) -> None:
    """Configure JWT parameters. Called at server startup.

    An empty ``secret`` is the "unconfigured" sentinel (used to reset/disable
    JWT, e.g. between tests) and is accepted. A NON-empty secret shorter than
    :data:`_MIN_SECRET_LEN` is rejected with ``ValueError`` — a weak HMAC key
    must never be accepted silently for HS256.
    """
    if secret and len(secret) < _MIN_SECRET_LEN:
        raise ValueError(
            f"JWT secret is too short ({len(secret)} chars); HS256 needs at least "
            f"{_MIN_SECRET_LEN}. Generate one with `secrets.token_urlsafe(32)` and "
            f"set it via KRYON_JWT_SECRET."
        )
    global _jwt_secret, _access_ttl_minutes
    _jwt_secret = secret
    _access_ttl_minutes = access_ttl_minutes
    # Initialize revocation DB on startup
    _get_revocation_db()


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
    """Revoke a token by its jti claim. Persisted to SQLite."""
    now = datetime.now(timezone.utc).timestamp()
    db_path = _get_revocation_db()
    try:
        conn = sqlite3.connect(str(db_path))
        conn.execute(
            "INSERT OR REPLACE INTO revoked_tokens (jti, exp, revoked_at) VALUES (?, ?, ?)",
            (jti, exp, now),
        )
        # Prune expired revocations
        conn.execute("DELETE FROM revoked_tokens WHERE exp < ?", (now,))
        conn.commit()
        conn.close()
    except Exception:
        logger.warning("Failed to persist token revocation", exc_info=True)


def is_token_revoked(jti: str) -> bool:
    """Check if a token has been revoked (SQLite lookup)."""
    db_path = _get_revocation_db()
    try:
        conn = sqlite3.connect(str(db_path))
        row = conn.execute("SELECT 1 FROM revoked_tokens WHERE jti = ?", (jti,)).fetchone()
        conn.close()
        return row is not None
    except Exception:
        logger.warning("Failed to check token revocation", exc_info=True)
        return False


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
