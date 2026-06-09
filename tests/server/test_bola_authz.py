"""BOLA / cross-client authorization regression for by-id endpoints.

Before the fix, by-id reads/mutations (GET /findings/{id}, the engagement
and scan by-id routes) looked the resource up by ID with no ownership check
— a scoped user could read or mutate another client's resources by guessing
an ID. The fix authorizes each by-id resource against the caller's assigned
clients and returns **404** (not 403) so existence isn't leaked.
"""

from __future__ import annotations

import pytest
from fastapi import HTTPException

import kryon.server.deps as deps_mod
from kryon.memory.models import FindingRecord
from kryon.server.auth.deps import get_current_user
from kryon.server.auth.isolation import require_resource_access
from kryon.server.auth.models import User

# --- unit-level: the guard itself --------------------------------------------


def _analyst(client_ids):
    user = User(username="a", email="a@t.com", password_hash="x", role="analyst")

    class _S:
        def get_user_client_ids(self, _uid):
            return list(client_ids)

    return user, _S()


@pytest.mark.unit
def test_guard_denies_foreign_client_with_404():
    user, store = _analyst(["client-A"])
    with pytest.raises(HTTPException) as exc:
        require_resource_access(user, "client-B", store, kind="Finding", resource_id="f1")
    assert exc.value.status_code == 404  # not 403 — hide existence


@pytest.mark.unit
def test_guard_allows_assigned_client():
    user, store = _analyst(["client-A", "client-B"])
    require_resource_access(user, "client-B", store, kind="Finding", resource_id="f1")


@pytest.mark.unit
def test_guard_admin_and_anon_pass():
    admin = User(username="adm", email="adm@t.com", password_hash="x", role="admin")
    require_resource_access(admin, "any-client", object(), kind="Finding", resource_id="f1")
    # No user (dev mode) → full access.
    require_resource_access(None, "any-client", object(), kind="Finding", resource_id="f1")


# --- endpoint-level: GET /findings/{id} ---------------------------------------


class _FakeStore:
    """Minimal store: one finding owned by ``client-B``."""

    def __init__(self, allowed_for_user):
        self._allowed = allowed_for_user

    def get_finding_by_id(self, finding_id):
        return FindingRecord(id=finding_id, scan_id="scan-1", client_id="client-B")

    def get_user_client_ids(self, _user_id):
        return list(self._allowed)


@pytest.fixture
def _override(app, monkeypatch):
    """Helper to wire a fake store + a given current user into the app."""

    def _apply(store, user):
        deps_mod._store = store
        app.dependency_overrides[get_current_user] = lambda: user

    yield _apply
    app.dependency_overrides.pop(get_current_user, None)


@pytest.mark.unit
def test_get_finding_blocks_cross_client(client, _override):
    # Analyst assigned to client-A only; the finding belongs to client-B.
    analyst = User(username="an", email="an@t.com", password_hash="x", role="analyst")
    _override(_FakeStore(allowed_for_user=["client-A"]), analyst)

    resp = client.get("/api/v1/findings/deadbeef")
    assert resp.status_code == 404


@pytest.mark.unit
def test_get_finding_allows_owner(client, _override):
    analyst = User(username="an", email="an@t.com", password_hash="x", role="analyst")
    _override(_FakeStore(allowed_for_user=["client-B"]), analyst)

    resp = client.get("/api/v1/findings/deadbeef")
    assert resp.status_code == 200
    assert resp.json()["client_id"] == "client-B"


@pytest.mark.unit
def test_get_finding_admin_full_access(client, _override):
    admin = User(username="adm", email="adm@t.com", password_hash="x", role="admin")
    _override(_FakeStore(allowed_for_user=[]), admin)

    resp = client.get("/api/v1/findings/deadbeef")
    assert resp.status_code == 200
