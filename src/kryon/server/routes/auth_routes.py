"""Authentication API endpoints — login, refresh, password change."""

from __future__ import annotations

import time
from collections import defaultdict
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from kryon.server.auth.deps import get_current_user
from kryon.server.auth.jwt_auth import (
    create_access_token,
    create_refresh_token,
    decode_token,
    is_jwt_configured,
    revoke_token,
)
from kryon.server.auth.models import User, UserPublic
from kryon.server.auth.password import hash_password, validate_password_complexity, verify_password
from kryon.server.deps import get_store
from kryon.server.logging_config import get_logger

logger = get_logger(__name__)

router = APIRouter(tags=["auth"])

# Login attempt tracking for brute-force protection (bounded)
_login_attempts: dict[str, list[float]] = defaultdict(list)
_MAX_ATTEMPTS = 5
_LOCKOUT_WINDOW = 900  # 15 minutes
_MAX_TRACKED_USERS = 10_000


class LoginRequest(BaseModel):
    username: str = Field(..., min_length=1, max_length=100)
    password: str = Field(..., min_length=1, max_length=200)


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    user: UserPublic


class RefreshRequest(BaseModel):
    refresh_token: str


class PasswordChangeRequest(BaseModel):
    current_password: str = Field(..., min_length=1)
    new_password: str = Field(..., min_length=8, max_length=200)


@router.post("/auth/login", response_model=TokenResponse)
async def login(req: LoginRequest):
    """Authenticate and receive JWT tokens."""
    if not is_jwt_configured():
        raise HTTPException(status_code=501, detail="JWT auth not configured")

    # Brute-force protection
    now = time.monotonic()
    # Evict oldest tracked users if at capacity
    if len(_login_attempts) > _MAX_TRACKED_USERS:
        excess = len(_login_attempts) - _MAX_TRACKED_USERS
        for key in list(_login_attempts.keys())[:excess]:
            del _login_attempts[key]
    attempts = _login_attempts[req.username]
    # Prune old attempts outside the lockout window
    _login_attempts[req.username] = [t for t in attempts if now - t < _LOCKOUT_WINDOW]
    if len(_login_attempts[req.username]) >= _MAX_ATTEMPTS:
        raise HTTPException(status_code=429, detail="Too many login attempts. Try again later.")

    store = get_store()
    user = store.get_user_by_username(req.username)
    if user is None or not verify_password(req.password, user.password_hash):
        _login_attempts[req.username].append(now)
        raise HTTPException(status_code=401, detail="Invalid username or password")

    if not user.is_active:
        raise HTTPException(status_code=403, detail="Account disabled")

    # Update last login
    store.update_user(user.id, last_login=datetime.now(timezone.utc).isoformat())

    logger.info("User logged in: %s", user.username)
    access = create_access_token(user.id, user.username, user.role)
    refresh = create_refresh_token(user.id)

    return TokenResponse(
        access_token=access,
        refresh_token=refresh,
        user=UserPublic(**user.model_dump()),
    )


@router.post("/auth/refresh", response_model=dict)
async def refresh_token(req: RefreshRequest):
    """Exchange a refresh token for a new access token."""
    if not is_jwt_configured():
        raise HTTPException(status_code=501, detail="JWT auth not configured")

    try:
        payload = decode_token(req.refresh_token)
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid or expired refresh token")

    if payload.get("type") != "refresh":
        raise HTTPException(status_code=401, detail="Invalid token type")

    store = get_store()
    user = store.get_user_by_id(payload["sub"])
    if user is None or not user.is_active:
        raise HTTPException(status_code=401, detail="User not found or inactive")

    access = create_access_token(user.id, user.username, user.role)
    return {"access_token": access, "token_type": "bearer"}


@router.get("/auth/me", response_model=UserPublic)
async def get_me(user: User | None = Depends(get_current_user)):
    """Get the currently authenticated user's info."""
    if user is None:
        raise HTTPException(status_code=401, detail="Not authenticated")
    return UserPublic(**user.model_dump())


@router.put("/auth/password")
async def change_password(req: PasswordChangeRequest, user: User | None = Depends(get_current_user)):
    """Change the current user's password."""
    if user is None:
        raise HTTPException(status_code=401, detail="Not authenticated")

    if not verify_password(req.current_password, user.password_hash):
        raise HTTPException(status_code=400, detail="Current password is incorrect")

    complexity_error = validate_password_complexity(req.new_password)
    if complexity_error:
        raise HTTPException(status_code=400, detail=complexity_error)

    store = get_store()
    store.update_user(user.id, password_hash=hash_password(req.new_password))
    logger.info("Password changed for user: %s", user.username)  # nosemgrep: python-logger-credential-disclosure
    return {"detail": "Password updated"}


class LogoutRequest(BaseModel):
    access_token: str = Field("", description="Access token to revoke (optional)")
    refresh_token: str = Field("", description="Refresh token to revoke (optional)")


@router.post("/auth/logout")
async def logout(req: LogoutRequest, user: User | None = Depends(get_current_user)):
    """Revoke tokens to log out."""
    if user is None:
        raise HTTPException(status_code=401, detail="Not authenticated")

    revoked = 0
    for token_str in (req.access_token, req.refresh_token):
        if not token_str:
            continue
        try:
            payload = decode_token(token_str)
            jti = payload.get("jti")
            exp = payload.get("exp", 0)
            if jti:
                revoke_token(jti, exp)
                revoked += 1
        except Exception:
            pass  # Token already invalid/expired

    logger.info("User logged out: %s (tokens revoked: %d)", user.username, revoked)
    return {"detail": "Logged out", "tokens_revoked": revoked}
