"""Tenant data isolation strategies."""

from __future__ import annotations

import abc
import logging
from pathlib import Path

logger = logging.getLogger(__name__)


class IsolationStrategy(abc.ABC):
    """Abstract base for tenant data isolation."""

    @abc.abstractmethod
    def get_store_for_tenant(self, tenant_id: str):
        """Get a MemoryStore instance for the given tenant."""

    @abc.abstractmethod
    def initialize_tenant(self, tenant_id: str) -> None:
        """Initialize storage for a new tenant."""

    @abc.abstractmethod
    def delete_tenant_data(self, tenant_id: str) -> None:
        """Delete all data for a tenant."""


class SeparateDatabaseStrategy(IsolationStrategy):
    """Each tenant gets a separate SQLite database file."""

    def __init__(self, base_dir: Path | None = None):
        self._base_dir = base_dir or (Path.home() / ".kryon" / "tenants")
        self._base_dir.mkdir(parents=True, exist_ok=True)
        self._stores: dict[str, object] = {}

    def _db_path(self, tenant_id: str) -> Path:
        return self._base_dir / f"tenant_{tenant_id}.db"

    def get_store_for_tenant(self, tenant_id: str):
        from kryon.memory.store import MemoryStore

        if tenant_id not in self._stores:
            db_path = self._db_path(tenant_id)
            self._stores[tenant_id] = MemoryStore(db_path=db_path)
            logger.debug("Created store for tenant %s at %s", tenant_id, db_path)
        return self._stores[tenant_id]

    def initialize_tenant(self, tenant_id: str) -> None:
        """Create the DB file and schema for a new tenant."""
        self.get_store_for_tenant(tenant_id)

    def delete_tenant_data(self, tenant_id: str) -> None:
        """Close and remove the tenant's database."""
        if tenant_id in self._stores:
            self._stores[tenant_id].close()
            del self._stores[tenant_id]
        db_path = self._db_path(tenant_id)
        if db_path.exists():
            db_path.unlink()
            logger.info("Deleted tenant DB: %s", db_path)


class SharedDatabaseStrategy(IsolationStrategy):
    """All tenants share one database — **NOT a supported multi-tenant mode.**

    Kryon's production posture is **single-tenant per deployment** (one
    client per instance / container; isolation is at the instance boundary).
    The business tables (clients, scans, findings, engagements,
    user_client_access) are *client*-scoped, not *tenant*-scoped — there is
    no ``tenant_id`` column to filter or purge by — so a shared database
    cannot actually isolate tenants. Use :class:`SeparateDatabaseStrategy`
    (a DB file per tenant) or one deployment per client instead.

    This class is retained only as a placeholder for a future true
    multi-tenant build; its destructive operation refuses to run rather than
    silently pretending to delete a tenant's data.
    """

    def __init__(self):
        self._store = None

    def get_store_for_tenant(self, tenant_id: str):
        from kryon.server.deps import get_store

        return get_store()

    def initialize_tenant(self, tenant_id: str) -> None:
        pass  # No special init needed for shared DB

    def delete_tenant_data(self, tenant_id: str) -> None:
        # Fail loud: silently no-op'ing a "delete all tenant data" call is a
        # data-retention/compliance hazard. Shared-DB multi-tenant deletion
        # is not implementable against the current client-centric schema.
        raise NotImplementedError(
            "SharedDatabaseStrategy does not support per-tenant deletion "
            "(the schema is client-scoped, not tenant-scoped). Use "
            "SeparateDatabaseStrategy or one deployment per client."
        )
