"""F199.O — Database-aware rule_id and engine-specific remediation.

Surfaceado en POC piloto Britimp 2026-05-18 contra .150: el check
_check_mysql flag-eaba CUALQUIER DB (PostgreSQL en este caso) con
rule_id 'mysql-exposed' y la remediation hablando de
require_secure_transport (MySQL-specific). PostgreSQL no tiene esa
config — usa hostssl en pg_hba.conf.

F199.O ahora produce rule_id + remediation por engine:
  mysql / postgresql / mongodb / redis
con fallback genérico cuando el banner no permite identificar.
"""

from __future__ import annotations

import os

os.environ.setdefault("OPENAI_API_KEY", "test_key_for_ci_environment")

import pytest

from kryon.cli.engage import DiscoveredService, _check_mysql, _resolve_database_engine


def _svc(*, port: int, service: str = "", product: str = "") -> DiscoveredService:
    return DiscoveredService(host="10.0.0.5", port=port, state="open", service=service, product=product)


# ---------------------------------------------------------------------------
# _resolve_database_engine — pure helper
# ---------------------------------------------------------------------------


class TestResolveEngineByServiceAndPort:
    def test_mysql_3306(self):
        meta = _resolve_database_engine(_svc(port=3306, service="mysql"))
        assert meta["engine"] == "mysql"
        assert meta["pretty"] == "MySQL"
        assert "require_secure_transport" in meta["remediation"]

    def test_mysql_x_protocol_33060(self):
        meta = _resolve_database_engine(_svc(port=33060, service="mysql"))
        assert meta["engine"] == "mysql"
        assert "X Protocol" in meta["pretty"] or "X Protocol" in meta["remediation"]

    def test_postgresql_5432(self):
        """The exact .150 case — Britimp PostgreSQL exposed."""
        meta = _resolve_database_engine(_svc(port=5432, service="postgresql"))
        assert meta["engine"] == "postgresql"
        assert meta["pretty"] == "PostgreSQL"
        assert "hostssl" in meta["remediation"] or "pg_hba" in meta["remediation"]

    def test_mongodb_27017(self):
        meta = _resolve_database_engine(_svc(port=27017, service="mongodb"))
        assert meta["engine"] == "mongodb"
        assert "MongoDB" in meta["pretty"]
        assert "requireTLS" in meta["remediation"]

    def test_redis_6379(self):
        meta = _resolve_database_engine(_svc(port=6379, service="redis"))
        assert meta["engine"] == "redis"
        assert "Redis" in meta["pretty"]
        assert "requirepass" in meta["remediation"] or "ACL" in meta["remediation"]


class TestResolveEngineByPortAlone:
    """When nmap couldn't grab the service banner (throttled scan), the
    port alone should still resolve to the right engine."""

    def test_5432_without_service_is_postgresql(self):
        meta = _resolve_database_engine(_svc(port=5432, service=""))
        assert meta["engine"] == "postgresql"

    def test_27017_without_service_is_mongodb(self):
        meta = _resolve_database_engine(_svc(port=27017, service=""))
        assert meta["engine"] == "mongodb"

    def test_6379_without_service_is_redis(self):
        meta = _resolve_database_engine(_svc(port=6379, service=""))
        assert meta["engine"] == "redis"


class TestResolveEngineFallback:
    """Unknown ports get a generic database entry, not a wrong engine."""

    def test_unknown_port_returns_generic(self):
        meta = _resolve_database_engine(_svc(port=12345, service=""))
        assert meta["engine"] == "database"
        assert "12345" in meta["pretty"]

    def test_unknown_port_with_service_returns_generic(self):
        meta = _resolve_database_engine(_svc(port=99999, service="oracle-tns"))
        assert meta["engine"] == "database"


# ---------------------------------------------------------------------------
# _check_mysql end-to-end
# ---------------------------------------------------------------------------


class TestCheckDatabaseEndToEnd:
    def test_britimp_h150_postgresql(self):
        """Regression: .150 had PostgreSQL on 5432, Kryon flag-eaba como
        'mysql-exposed' (wrong rule_id) y remediation MySQL-only (wrong)."""
        svc = _svc(port=5432, service="postgresql")
        findings = _check_mysql(svc)
        assert len(findings) == 1
        f = findings[0]
        assert f.rule_id == "postgresql-exposed", f"expected postgresql-exposed, got {f.rule_id}"
        assert "PostgreSQL" in f.message
        assert "hostssl" in f.remediation or "pg_hba" in f.remediation
        assert f.severity == "HIGH"
        assert f.cwe == "CWE-319"

    def test_mysql_3306(self):
        svc = _svc(port=3306, service="mysql", product="MySQL 8.0.44")
        findings = _check_mysql(svc)
        assert len(findings) == 1
        assert findings[0].rule_id == "mysql-exposed"
        assert "MySQL" in findings[0].message

    def test_mongodb_27017(self):
        svc = _svc(port=27017, service="mongodb")
        findings = _check_mysql(svc)
        assert len(findings) == 1
        assert findings[0].rule_id == "mongodb-exposed"
        assert "MongoDB" in findings[0].message

    def test_redis_6379(self):
        svc = _svc(port=6379, service="redis")
        findings = _check_mysql(svc)
        assert len(findings) == 1
        assert findings[0].rule_id == "redis-exposed"
        assert "Redis" in findings[0].message

    def test_unknown_port_uses_generic_rule_id(self):
        svc = _svc(port=15432, service="postgresql")
        findings = _check_mysql(svc)
        assert len(findings) == 1
        # Unknown port → falls back to generic "database-exposed", not the wrong one.
        assert findings[0].rule_id == "database-exposed"
