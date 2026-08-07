"""User model for enterprise authentication."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Literal

from pydantic import BaseModel, Field


class User(BaseModel):
    """Represents a KRYON platform user."""

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    username: str
    email: str
    password_hash: str = ""
    role: Literal["admin", "analyst", "viewer"] = "analyst"
    is_active: bool = True
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    last_login: str | None = None


class UserPublic(BaseModel):
    """User data safe to return in API responses (no password hash)."""

    id: str
    username: str
    email: str
    role: str
    is_active: bool
    created_at: str
    last_login: str | None = None
