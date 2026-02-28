"""Tests for asset importer."""

import pytest
from kryon.onboarding.importer import import_assets_csv, import_assets_json, validate_scope
from kryon.memory.store import MemoryStore


@pytest.fixture
def store(tmp_path):
    s = MemoryStore(db_path=tmp_path / "test.db")
    yield s
    s.close()


def test_import_csv(store):
    """Test importing assets from CSV string."""
    csv_data = "identifier,asset_type\nweb-server-01,host\ndb-server-01,database\n"
    count = import_assets_csv(csv_data, "client-1", store)
    assert count == 2
    assets = store.list_assets(client_id="client-1")
    assert len(assets) == 2


def test_import_csv_empty(store):
    """Test importing empty CSV."""
    csv_data = "identifier,asset_type\n"
    count = import_assets_csv(csv_data, "client-1", store)
    assert count == 0


def test_import_csv_missing_identifier(store):
    """Test CSV rows with empty identifier are skipped."""
    csv_data = "identifier,asset_type\n,host\nvalid-host,host\n"
    count = import_assets_csv(csv_data, "client-1", store)
    assert count == 1


def test_import_json(store):
    """Test importing assets from JSON string."""
    json_data = '[{"identifier": "app-server-01", "asset_type": "host"}, {"identifier": "mail-server", "asset_type": "mail"}]'
    count = import_assets_json(json_data, "client-1", store)
    assert count == 2


def test_import_json_invalid(store):
    """Test importing invalid JSON returns 0."""
    count = import_assets_json("not json", "client-1", store)
    assert count == 0


def test_validate_scope_localhost():
    """Test scope validation resolves localhost."""
    results = validate_scope(["localhost"])
    assert len(results) == 1
    assert results[0]["target"] == "localhost"
    # localhost should resolve
    assert results[0]["reachable"] is True


def test_validate_scope_invalid():
    """Test scope validation for invalid hostname."""
    results = validate_scope(["this-host-does-not-exist-12345.invalid"])
    assert len(results) == 1
    assert results[0]["reachable"] is False


def test_validate_scope_empty():
    """Test scope validation with empty targets."""
    results = validate_scope(["", "  "])
    assert len(results) == 0
