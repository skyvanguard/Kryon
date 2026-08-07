"""Tests for User model and store CRUD operations."""

import pytest

from kryon.memory.store import MemoryStore
from kryon.server.auth.models import User
from kryon.server.auth.password import hash_password


@pytest.fixture
def store(tmp_path):
    s = MemoryStore(db_path=tmp_path / "test.db")
    yield s
    s.close()


@pytest.fixture
def sample_user():
    return User(
        username="analyst1",
        email="analyst1@test.com",
        password_hash=hash_password("secret123"),
        role="analyst",
    )


def test_create_and_get_user(store, sample_user):
    store.create_user(sample_user)
    fetched = store.get_user_by_username("analyst1")
    assert fetched is not None
    assert fetched.username == "analyst1"
    assert fetched.email == "analyst1@test.com"
    assert fetched.role == "analyst"
    assert fetched.is_active is True


def test_get_user_by_id(store, sample_user):
    store.create_user(sample_user)
    fetched = store.get_user_by_id(sample_user.id)
    assert fetched is not None
    assert fetched.username == "analyst1"


def test_list_users(store, sample_user):
    store.create_user(sample_user)
    store.create_user(
        User(
            username="admin1",
            email="admin@test.com",
            password_hash=hash_password("admin"),
            role="admin",
        )
    )
    users = store.list_users()
    assert len(users) == 2


def test_update_user(store, sample_user):
    store.create_user(sample_user)
    store.update_user(sample_user.id, role="admin")
    fetched = store.get_user_by_id(sample_user.id)
    assert fetched.role == "admin"


def test_delete_user(store, sample_user):
    store.create_user(sample_user)
    assert store.delete_user(sample_user.id) is True
    assert store.get_user_by_id(sample_user.id) is None


def test_user_client_access(store, sample_user):
    store.create_user(sample_user)
    store.assign_client_to_user(sample_user.id, "client-001")
    store.assign_client_to_user(sample_user.id, "client-002")
    ids = store.get_user_client_ids(sample_user.id)
    assert set(ids) == {"client-001", "client-002"}

    store.remove_client_from_user(sample_user.id, "client-001")
    ids = store.get_user_client_ids(sample_user.id)
    assert ids == ["client-002"]


def test_user_not_found(store):
    assert store.get_user_by_username("nobody") is None
    assert store.get_user_by_id("no-id") is None
