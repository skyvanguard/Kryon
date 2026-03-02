"""Authentication API endpoints — login, refresh, password change."""

from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from kryon.server.auth.deps import get_current_user
from kryon.server.auth.jwt_auth import (
    create_access_token,
    create_refresh_token,
    decode_token,
    is_jwt_configured,
)
from kryon.server.auth.models import User, UserPublic
from kryon.server.auth.password import hash_password, validate_password_complexity, verify_password
from kryon.server.deps import get_store
from kryon.server.logging_config import get_logger

logger = get_logger(__name__)

router = APIRouter(tags=["auth"])


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

    store = get_store()
    user = store.get_user_by_username(req.username)
    if user is None or not verify_password(req.password, user.password_hash):
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
    logger.info("Password changed for user: %s", user.username)
    return {"detail": "Password updated"}
