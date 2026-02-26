"""Client isolation — users only see clients they're assigned to."""

from __future__ import annotations

from fastapi import HTTPException

from kryon.server.auth.models import User


def get_accessible_client_ids(user: User | None, store) -> set[str] | None:
    """Get the set of client IDs accessible to the user.

    Returns None if the user can access all clients (admin or no auth).
    """
    if user is None:
        return None  # No JWT auth — full access
    if user.role == "admin":
        return None  # Admin sees everything
    return set(store.get_user_client_ids(user.id))


def verify_client_access(user: User | None, client_id: str, store) -> None:
    """Raise 403 if the user cannot access this client."""
    accessible = get_accessible_client_ids(user, store)
    if accessible is None:
        return  # Full access
    if client_id not in accessible:
        raise HTTPException(status_code=403, detail="Access denied to this client")
