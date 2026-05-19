"""F202.J — Microsoft SQL Server exposure check.

Surface ground truth POC Britimp 2026-05-18 contra .15: Microsoft
SQL Server 2019 (15.00.4455) escuchando en :1433 abierto al segmento
sin TLS check automatico. F199.O original cubria solo MySQL /
PostgreSQL / MongoDB / Redis — sin SQL Server, todo cliente bancario
con stack Microsoft (Britimp incluido) quedaba sin deteccion
automatica de DB exposure.

F202.J extiende _DATABASE_ENGINES + dispatch loop:
  - ms-sql-s + 1433  -> mssql (TDS service)
  - ms-sql + 1433    -> mssql (alt service name)
  - ms-sql-m + 1434  -> mssql-browser (Browser instance discovery)
"""

from __future__ import annotations

import os

os.environ.setdefault("OPENAI_API_KEY", "test_key_for_ci_environment")

import pytest

from kryon.cli.engage import (
    _DATABASE_ENGINES,
    DiscoveredService,
    _check_mysql,
    _resolve_database_engine,
)


def _svc(
    port: int,
    service: str = "",
    product: str = "",
    version: str = "",
    state: str = "open",
) -> DiscoveredService:
    return DiscoveredService(
        host="h",
        port=port,
        state=state,
        service=service,
        product=product,
        version=version,
    )


# ---------------------------------------------------------------------------
# F202.J — MSSQL detection by service + port
# ---------------------------------------------------------------------------


class TestMssqlResolution:
    def test_britimp_h15_scenario(self):
        """Reproduces the .15 case: ms-sql-s service on tcp/1433 with
        Microsoft SQL Server 2019 banner. Must resolve to mssql engine."""
        svc = _svc(1433, "ms-sql-s", "Microsoft SQL Server 2019", "15.00.4455")
        meta = _resolve_database_engine(svc)
        assert meta["engine"] == "mssql"
        assert "Microsoft SQL Server" in meta["pretty"]
        assert "TLS" in meta["remediation"] or "Encryption" in meta["remediation"]

    def test_ms_sql_alt_service_name(self):
        svc = _svc(1433, "ms-sql")
        meta = _resolve_database_engine(svc)
        assert meta["engine"] == "mssql"

    def test_mssql_browser_1434(self):
        svc = _svc(1434, "ms-sql-m")
        meta = _resolve_database_engine(svc)
        assert meta["engine"] == "mssql-browser"
        assert "Browser" in meta["pretty"]
        # Remediation should mention the recon-leak risk
        assert "instancia" in meta["remediation"].lower() or "named-instance" in meta["remediation"].lower()


# ---------------------------------------------------------------------------
# F202.J — Full finding emission via _check_mysql
# ---------------------------------------------------------------------------


class TestMssqlFinding:
    def test_finding_rule_id_is_mssql_exposed(self):
        svc = _svc(1433, "ms-sql-s", "Microsoft SQL Server 2019", "15.00.4455")
        findings = _check_mysql(svc)
        assert len(findings) == 1
        f = findings[0]
        assert f.rule_id == "mssql-exposed"
        assert f.severity == "HIGH"
        assert f.cwe == "CWE-319"
        assert "Microsoft SQL Server" in f.message
        assert ":1433" in f.host

    def test_finding_evidence_includes_banner(self):
        svc = _svc(1433, "ms-sql-s", "Microsoft SQL Server 2019", "15.00.4455")
        findings = _check_mysql(svc)
        f = findings[0]
        assert "Microsoft SQL Server 2019" in f.evidence
        assert "1433" in f.evidence

    def test_browser_finding_rule_id_is_browser(self):
        svc = _svc(1434, "ms-sql-m")
        findings = _check_mysql(svc)
        assert findings[0].rule_id == "mssql-browser-exposed"


# ---------------------------------------------------------------------------
# F202.J — Regression: existing engines unaffected
# ---------------------------------------------------------------------------


class TestNoRegressionExistingEngines:
    def test_mysql_3306_still_works(self):
        svc = _svc(3306, "mysql")
        meta = _resolve_database_engine(svc)
        assert meta["engine"] == "mysql"

    def test_postgresql_5432_still_works(self):
        svc = _svc(5432, "postgresql")
        meta = _resolve_database_engine(svc)
        assert meta["engine"] == "postgresql"

    def test_mongodb_27017_still_works(self):
        svc = _svc(27017, "mongodb")
        meta = _resolve_database_engine(svc)
        assert meta["engine"] == "mongodb"

    def test_redis_6379_still_works(self):
        svc = _svc(6379, "redis")
        meta = _resolve_database_engine(svc)
        assert meta["engine"] == "redis"


# ---------------------------------------------------------------------------
# F202.J — Port-only fallback (when nmap couldn't grab the banner)
# ---------------------------------------------------------------------------


class TestPortOnlyFallback:
    def test_1433_no_service_name_resolves_mssql(self):
        """nmap may fail version detection on a heavily firewalled
        host. Port-only resolution must still classify 1433 as MSSQL
        (not generic 'database')."""
        svc = _svc(1433, "")
        meta = _resolve_database_engine(svc)
        # The fallback walks _DATABASE_ENGINES; the first entry whose
        # port matches wins. We have two 1433 entries (ms-sql-s and
        # ms-sql) — whichever wins, engine should be 'mssql' not
        # 'database' generic.
        assert meta["engine"] == "mssql"

    def test_1434_no_service_resolves_browser(self):
        svc = _svc(1434, "")
        meta = _resolve_database_engine(svc)
        assert meta["engine"] == "mssql-browser"


# ---------------------------------------------------------------------------
# F202.J — Engine table sanity
# ---------------------------------------------------------------------------


class TestEngineTableSanity:
    def test_mssql_entries_present(self):
        assert ("ms-sql-s", 1433) in _DATABASE_ENGINES
        assert ("ms-sql", 1433) in _DATABASE_ENGINES
        assert ("ms-sql-m", 1434) in _DATABASE_ENGINES

    def test_mssql_remediation_banking_relevant(self):
        meta = _DATABASE_ENGINES[("ms-sql-s", 1433)]
        # The remediation should mention SQL Server Config Manager
        # (the canonical place to set Force Encryption) AND mention
        # Windows Auth as the preferred mode for banking.
        assert "Configuration Manager" in meta["remediation"]
        assert "Windows Auth" in meta["remediation"]
