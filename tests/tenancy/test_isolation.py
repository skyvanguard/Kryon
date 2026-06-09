"""Tests for tenant data isolation strategies."""

from __future__ import annotations

import shutil
import tempfile
from pathlib import Path

import pytest

from kryon.tenancy.isolation import SeparateDatabaseStrategy, SharedDatabaseStrategy


class TestSeparateDatabaseStrategy:
    @pytest.fixture
    def base_dir(self, tmp_path):
        d = tmp_path / "tenants"
        d.mkdir()
        return d

    def test_creates_separate_dbs(self, base_dir):
        strategy = SeparateDatabaseStrategy(base_dir=base_dir)
        store_a = strategy.get_store_for_tenant("tenant-a")
        store_b = strategy.get_store_for_tenant("tenant-b")
        assert store_a is not store_b
        assert (base_dir / "tenant_tenant-a.db").exists()
        assert (base_dir / "tenant_tenant-b.db").exists()

    def test_no_cross_tenant_data(self, base_dir):
        strategy = SeparateDatabaseStrategy(base_dir=base_dir)
        store_a = strategy.get_store_for_tenant("tenant-a")
        store_b = strategy.get_store_for_tenant("tenant-b")

        # Create client in tenant A
        from kryon.memory.models import Client

        client = Client(name="Test Client")
        store_a.create_client(client)

        # Tenant B should have no clients
        clients_b = store_b.list_clients()
        assert len(clients_b) == 0

    def test_same_tenant_returns_cached_store(self, base_dir):
        strategy = SeparateDatabaseStrategy(base_dir=base_dir)
        store1 = strategy.get_store_for_tenant("tenant-x")
        store2 = strategy.get_store_for_tenant("tenant-x")
        assert store1 is store2

    def test_initialize_tenant(self, base_dir):
        strategy = SeparateDatabaseStrategy(base_dir=base_dir)
        strategy.initialize_tenant("new-tenant")
        assert (base_dir / "tenant_new-tenant.db").exists()

    def test_delete_tenant_data(self, base_dir):
        strategy = SeparateDatabaseStrategy(base_dir=base_dir)
        strategy.initialize_tenant("doomed")
        assert (base_dir / "tenant_doomed.db").exists()
        strategy.delete_tenant_data("doomed")
        assert not (base_dir / "tenant_doomed.db").exists()

    def test_schema_init_per_tenant(self, base_dir):
        strategy = SeparateDatabaseStrategy(base_dir=base_dir)
        store = strategy.get_store_for_tenant("schema-test")
        # Should be able to create clients (schema initialized)
        from kryon.memory.models import Client

        client = Client(name="Schema Test")
        store.create_client(client)
        clients = store.list_clients()
        assert len(clients) == 1


class TestSharedDatabaseStrategy:
    def test_returns_store(self):
        strategy = SharedDatabaseStrategy()
        # Should not raise
        assert strategy is not None

    def test_initialize_no_error(self):
        strategy = SharedDatabaseStrategy()
        strategy.initialize_tenant("test-123")  # Should not raise

    def test_delete_tenant_data_refuses(self):
        """Per-tenant deletion must fail loud, not silently no-op — silently
        'deleting' a tenant's data is a data-retention/compliance hazard."""
        strategy = SharedDatabaseStrategy()
        with pytest.raises(NotImplementedError):
            strategy.delete_tenant_data("some-tenant")
