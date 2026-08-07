"""Client isolation — users only see clients they're assigned to."""

from __future__ import annotations

from fastapi import HTTPException

from kryon.server.auth.models import User
from kryon.server.exceptions import not_found


def get_accessible_client_ids(user: User | None, store) -> set[str] | None:
    """Get the set of client IDs accessible to the user.

    Returns None if the user can access all clients (admin or no auth).
    """
    if user is None:
        return None  # No JWT auth — full access
    if user.role == "admin":
        return None  # Admin sees everything
    return set(store.get_user_client_ids(user.id))


def can_access_client(user: User | None, client_id: str, store) -> bool:
    """True if ``user`` may access ``client_id``'s resources."""
    accessible = get_accessible_client_ids(user, store)
    return accessible is None or client_id in accessible


def verify_client_access(user: User | None, client_id: str, store) -> None:
    """Raise 403 if the user cannot access this client.

    Used on *create* paths where the client_id is operator-supplied — a 403
    is the honest answer there (the caller named the client explicitly).
    """
    if not can_access_client(user, client_id, store):
        raise HTTPException(status_code=403, detail="Access denied to this client")


def require_resource_access(
    user: User | None,
    client_id: str,
    store,
    *,
    kind: str,
    resource_id: str,
) -> None:
    """Guard a by-id resource read/mutation against cross-client access.

    Unlike :func:`verify_client_access`, this raises **404** (not 403) when
    the caller lacks access, so an unauthorized user cannot tell an existing
    foreign resource ID apart from a non-existent one (anti-enumeration /
    BOLA hardening).
    """
    if not can_access_client(user, client_id, store):
        raise not_found(kind, resource_id)
