"""F202.K — Oracle Database TNS Listener exposure check.

Companion to F202.J. Completa el coverage banking-critical: muchos
core-banking suites de LATAM (T24, Flexcube, Finacle, Bantotal) corren
sobre Oracle DB. TNS Listener en :1521 sin TCPS = HIGH CWE-319.

Tres signatures cubiertos:
  - service=oracle-tns + port=1521   (default canonical)
  - service=oracle-tns + port=1522   (alternate, no-default-port hardening)
  - service=tns + port=1521          (legacy nmap service name)

Port-only fallback (banner suppression) tambien funciona.
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
# F202.K — Resolution by service + port
# ---------------------------------------------------------------------------


class TestOracleResolution:
    def test_oracle_tns_1521_resolves(self):
        svc = _svc(1521, "oracle-tns", "Oracle TNS Listener", "11.2.0.4.0")
        meta = _resolve_database_engine(svc)
        assert meta["engine"] == "oracle"
        assert "Oracle" in meta["pretty"]

    def test_oracle_tns_1522_alternate_port(self):
        svc = _svc(1522, "oracle-tns")
        meta = _resolve_database_engine(svc)
        assert meta["engine"] == "oracle"
        assert "alternate" in meta["pretty"].lower()

    def test_tns_legacy_service_name(self):
        svc = _svc(1521, "tns")
        meta = _resolve_database_engine(svc)
        assert meta["engine"] == "oracle"

    def test_remediation_mentions_tcps(self):
        svc = _svc(1521, "oracle-tns")
        meta = _resolve_database_engine(svc)
        assert "TCPS" in meta["remediation"]

    def test_remediation_mentions_tns_poison_cve(self):
        """The remediation must mention CVE-2012-1675 / TNS Poison and
        ADMIN_RESTRICTIONS — that's the banca-specific advice that
        differentiates from generic 'enable TLS'."""
        svc = _svc(1521, "oracle-tns")
        meta = _resolve_database_engine(svc)
        assert "CVE-2012-1675" in meta["remediation"] or "TNS Poison" in meta["remediation"]
        assert "ADMIN_RESTRICTIONS" in meta["remediation"]


# ---------------------------------------------------------------------------
# F202.K — Full finding emission via _check_mysql
# ---------------------------------------------------------------------------


class TestOracleFinding:
    def test_finding_rule_id_is_oracle_exposed(self):
        svc = _svc(1521, "oracle-tns", "Oracle TNS Listener", "11.2.0.4.0")
        findings = _check_mysql(svc)
        assert len(findings) == 1
        f = findings[0]
        assert f.rule_id == "oracle-exposed"
        assert f.severity == "HIGH"
        assert f.cwe == "CWE-319"
        assert "Oracle" in f.message
        assert ":1521" in f.host

    def test_finding_evidence_includes_banner(self):
        svc = _svc(1521, "oracle-tns", "Oracle TNS Listener", "11.2.0.4.0")
        findings = _check_mysql(svc)
        f = findings[0]
        assert "Oracle" in f.evidence
        assert "1521" in f.evidence


# ---------------------------------------------------------------------------
# F202.K — Port-only fallback
# ---------------------------------------------------------------------------


class TestPortOnlyFallback:
    def test_1521_no_service_resolves_oracle(self):
        """nmap may fail version detection on firewalled DBs.
        Port-only resolution must still tag oracle (not generic)."""
        svc = _svc(1521, "")
        meta = _resolve_database_engine(svc)
        assert meta["engine"] == "oracle"

    def test_1522_no_service_resolves_oracle(self):
        svc = _svc(1522, "")
        meta = _resolve_database_engine(svc)
        assert meta["engine"] == "oracle"


# ---------------------------------------------------------------------------
# F202.K — No regression on existing engines
# ---------------------------------------------------------------------------


class TestNoRegression:
    def test_mssql_1433_still_mssql(self):
        svc = _svc(1433, "ms-sql-s")
        meta = _resolve_database_engine(svc)
        assert meta["engine"] == "mssql"

    def test_mysql_3306_still_mysql(self):
        svc = _svc(3306, "mysql")
        meta = _resolve_database_engine(svc)
        assert meta["engine"] == "mysql"

    def test_postgresql_5432_still_postgresql(self):
        svc = _svc(5432, "postgresql")
        meta = _resolve_database_engine(svc)
        assert meta["engine"] == "postgresql"


# ---------------------------------------------------------------------------
# F202.K — Engine table sanity
# ---------------------------------------------------------------------------


class TestEngineTableSanity:
    def test_oracle_entries_present(self):
        assert ("oracle-tns", 1521) in _DATABASE_ENGINES
        assert ("oracle-tns", 1522) in _DATABASE_ENGINES
        assert ("tns", 1521) in _DATABASE_ENGINES

    def test_banking_specific_remediation(self):
        meta = _DATABASE_ENGINES[("oracle-tns", 1521)]
        # Banking-LATAM context must be mentioned
        assert (
            "core-banking" in meta["remediation"].lower()
            or "Banca-LATAM" in meta["remediation"]
        )
