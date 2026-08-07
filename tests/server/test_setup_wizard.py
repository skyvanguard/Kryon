"""Tests for the first-run setup wizard."""

import pytest

from kryon.memory.store import MemoryStore
from kryon.server.setup.env_writer import generate_jwt_secret, write_env_file
from kryon.server.setup.wizard import needs_setup


def test_needs_setup_empty_db(tmp_path):
    """Needs setup when no users exist."""
    db_path = tmp_path / "empty.db"
    assert needs_setup(db_path=db_path) is True


def test_needs_setup_with_user(tmp_path):
    """Does not need setup when admin exists."""
    from kryon.server.auth.models import User
    from kryon.server.auth.password import hash_password

    db_path = tmp_path / "setup.db"
    store = MemoryStore(db_path=db_path)
    store.create_user(
        User(
            username="admin",
            email="a@t.com",
            password_hash=hash_password("test1234"),
            role="admin",
        )
    )
    store.close()

    assert needs_setup(db_path=db_path) is False


def test_generate_jwt_secret():
    """JWT secret should be sufficiently long and random."""
    s1 = generate_jwt_secret()
    s2 = generate_jwt_secret()
    assert len(s1) >= 32
    assert s1 != s2


def test_write_env_file(tmp_path):
    """write_env_file creates a valid .env file."""
    path = write_env_file(
        jwt_secret="test-secret",
        cors_origins="http://localhost:3000",
        env_dir=tmp_path,
    )
    assert path.exists()
    content = path.read_text()
    assert "KRYON_JWT_SECRET=test-secret" in content
    assert "KRYON_CORS_ORIGINS=http://localhost:3000" in content
