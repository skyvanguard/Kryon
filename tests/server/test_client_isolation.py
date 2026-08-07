"""Tests for client isolation — users only see assigned clients."""

import pytest

from kryon.memory.store import MemoryStore
from kryon.server.auth.isolation import get_accessible_client_ids, verify_client_access
from kryon.server.auth.models import User
from kryon.server.auth.password import hash_password


@pytest.fixture
def store(tmp_path):
    s = MemoryStore(db_path=tmp_path / "isolation.db")
    yield s
    s.close()


@pytest.fixture
def admin_user():
    return User(username="admin", email="a@t.com", password_hash="x", role="admin")


@pytest.fixture
def analyst_user(store):
    user = User(username="analyst1", email="an@t.com", password_hash="x", role="analyst")
    store.create_user(user)
    store.assign_client_to_user(user.id, "client-A")
    store.assign_client_to_user(user.id, "client-B")
    return user


def test_none_user_full_access(store):
    """No user (dev mode) has full access."""
    result = get_accessible_client_ids(None, store)
    assert result is None


def test_admin_full_access(store, admin_user):
    """Admin sees everything."""
    result = get_accessible_client_ids(admin_user, store)
    assert result is None


def test_analyst_sees_assigned(store, analyst_user):
    """Analyst only sees assigned clients."""
    result = get_accessible_client_ids(analyst_user, store)
    assert result == {"client-A", "client-B"}


def test_verify_access_allowed(store, analyst_user):
    """No exception for allowed client."""
    verify_client_access(analyst_user, "client-A", store)


def test_verify_access_denied(store, analyst_user):
    """HTTPException 403 for unauthorized client."""
    from fastapi import HTTPException

    with pytest.raises(HTTPException) as exc_info:
        verify_client_access(analyst_user, "client-X", store)
    assert exc_info.value.status_code == 403
