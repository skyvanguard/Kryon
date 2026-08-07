"""F202.W — MySQL deep audit (con creds) detector tests.

Surfaced docker/vulnerable-lab target-db: ground truth incluye
bind 0.0.0.0 + sin require_secure_transport + local_infile=1. Sin
creds, _check_mysql solo emite "mysql-exposed" generico (~33%
coverage). Con KRYON_DB_USER + KRYON_DB_PASSWORD, _check_mysql_deep
conecta via pymysql y emite findings detallados.
"""

from __future__ import annotations

import os
import sys
from unittest.mock import MagicMock, patch

os.environ.setdefault("OPENAI_API_KEY", "test_key_for_ci_environment")

import pytest

from kryon.cli.engage import DiscoveredService, _check_mysql_deep


def _svc(port: int = 3306, host: str = "10.0.0.1", state: str = "open") -> DiscoveredService:
    return DiscoveredService(host=host, port=port, state=state, service="mysql", product="MySQL")


class _FakeCursor:
    def __init__(self, results: dict[str, tuple]):
        self._results = results
        self._last = None

    def execute(self, query: str):
        self._last = query

    def fetchone(self):
        for key, val in self._results.items():
            if self._last and key in self._last:
                return val
        return None


class _FakeConn:
    def __init__(self, results: dict[str, tuple]):
        self._cur = _FakeCursor(results)

    def cursor(self):
        return self._cur

    def close(self):
        pass


def _patch_pymysql(results: dict[str, tuple]):
    """Stub pymysql.connect via sys.modules patch."""
    fake = MagicMock()
    fake.connect.return_value = _FakeConn(results)
    return patch.dict(sys.modules, {"pymysql": fake})


def _patch_env(user: str = "app", password: str = "changeme"):
    return patch.dict(
        os.environ,
        {"KRYON_DB_USER": user, "KRYON_DB_PASSWORD": password},
    )


# ---------------------------------------------------------------------------
# Soft dep + creds gating
# ---------------------------------------------------------------------------


class TestGracefulSkip:
    def test_no_creds_skip(self):
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("KRYON_DB_USER", None)
            os.environ.pop("KRYON_DB_PASSWORD", None)
            findings = _check_mysql_deep(_svc())
        assert findings == []

    def test_closed_port_skip(self):
        with _patch_env():
            findings = _check_mysql_deep(_svc(state="closed"))
        assert findings == []

    def test_non_mysql_port_skip(self):
        with _patch_env():
            findings = _check_mysql_deep(_svc(port=5432))
        assert findings == []

    def test_pymysql_missing_skip(self):
        with _patch_env(), patch.dict(sys.modules, {"pymysql": None}):
            findings = _check_mysql_deep(_svc())
        assert findings == []

    def test_connect_failure_skip(self):
        fake = MagicMock()
        fake.connect.side_effect = Exception("auth failed")
        with _patch_env(), patch.dict(sys.modules, {"pymysql": fake}):
            findings = _check_mysql_deep(_svc())
        assert findings == []


# ---------------------------------------------------------------------------
# CWE-668 — bind 0.0.0.0
# ---------------------------------------------------------------------------


class TestBindPublic:
    def test_bind_0000_flags_high(self):
        results = {
            "bind_address": ("0.0.0.0",),
            "require_secure_transport": (1,),
            "have_ssl": ("have_ssl", "YES"),
            "local_infile": (0,),
            "VERSION()": ("8.0.46",),
        }
        with _patch_env(), _patch_pymysql(results):
            findings = _check_mysql_deep(_svc())
        rule_ids = [f.rule_id for f in findings]
        assert "mysql-bind-public" in rule_ids
        f = next(f for f in findings if f.rule_id == "mysql-bind-public")
        assert f.severity == "HIGH"
        assert f.cwe == "CWE-668"
        assert "0.0.0.0" in f.message

    def test_bind_ipv6_any_flags_high(self):
        results = {
            "bind_address": ("::",),
            "require_secure_transport": (1,),
            "have_ssl": ("have_ssl", "YES"),
            "local_infile": (0,),
            "VERSION()": ("8.0.46",),
        }
        with _patch_env(), _patch_pymysql(results):
            findings = _check_mysql_deep(_svc())
        rule_ids = [f.rule_id for f in findings]
        assert "mysql-bind-public" in rule_ids

    def test_bind_internal_ip_no_finding(self):
        results = {
            "bind_address": ("10.0.1.5",),
            "require_secure_transport": (1,),
            "have_ssl": ("have_ssl", "YES"),
            "local_infile": (0,),
            "VERSION()": ("8.0.46",),
        }
        with _patch_env(), _patch_pymysql(results):
            findings = _check_mysql_deep(_svc())
        rule_ids = [f.rule_id for f in findings]
        assert "mysql-bind-public" not in rule_ids


# ---------------------------------------------------------------------------
# CWE-319 — TLS available pero NO required
# ---------------------------------------------------------------------------


class TestTlsNotRequired:
    def test_have_ssl_yes_but_not_required(self):
        results = {
            "bind_address": ("10.0.1.5",),
            "require_secure_transport": (0,),
            "have_ssl": ("have_ssl", "YES"),
            "local_infile": (0,),
            "VERSION()": ("8.0.46",),
        }
        with _patch_env(), _patch_pymysql(results):
            findings = _check_mysql_deep(_svc())
        rule_ids = [f.rule_id for f in findings]
        assert "mysql-tls-not-required" in rule_ids
        f = next(f for f in findings if f.rule_id == "mysql-tls-not-required")
        assert f.cwe == "CWE-319"
        assert f.severity == "HIGH"

    def test_require_ssl_on_no_finding(self):
        results = {
            "bind_address": ("10.0.1.5",),
            "require_secure_transport": (1,),
            "have_ssl": ("have_ssl", "YES"),
            "local_infile": (0,),
            "VERSION()": ("8.0.46",),
        }
        with _patch_env(), _patch_pymysql(results):
            findings = _check_mysql_deep(_svc())
        rule_ids = [f.rule_id for f in findings]
        assert "mysql-tls-not-required" not in rule_ids


# ---------------------------------------------------------------------------
# CWE-200 — local_infile
# ---------------------------------------------------------------------------


class TestLocalInfile:
    def test_local_infile_enabled_medium(self):
        results = {
            "bind_address": ("10.0.1.5",),
            "require_secure_transport": (1,),
            "have_ssl": ("have_ssl", "YES"),
            "local_infile": (1,),
            "VERSION()": ("8.0.46",),
        }
        with _patch_env(), _patch_pymysql(results):
            findings = _check_mysql_deep(_svc())
        rule_ids = [f.rule_id for f in findings]
        assert "mysql-local-infile-enabled" in rule_ids
        f = next(f for f in findings if f.rule_id == "mysql-local-infile-enabled")
        assert f.severity == "MEDIUM"
        assert f.cwe == "CWE-200"

    def test_local_infile_disabled_no_finding(self):
        results = {
            "bind_address": ("10.0.1.5",),
            "require_secure_transport": (1,),
            "have_ssl": ("have_ssl", "YES"),
            "local_infile": (0,),
            "VERSION()": ("8.0.46",),
        }
        with _patch_env(), _patch_pymysql(results):
            findings = _check_mysql_deep(_svc())
        rule_ids = [f.rule_id for f in findings]
        assert "mysql-local-infile-enabled" not in rule_ids


# ---------------------------------------------------------------------------
# CWE-1104 — version EOL
# ---------------------------------------------------------------------------


class TestVersionEol:
    def test_mysql_57_eol(self):
        results = {
            "bind_address": ("10.0.1.5",),
            "require_secure_transport": (1,),
            "have_ssl": ("have_ssl", "YES"),
            "local_infile": (0,),
            "VERSION()": ("5.7.40",),
        }
        with _patch_env(), _patch_pymysql(results):
            findings = _check_mysql_deep(_svc())
        rule_ids = [f.rule_id for f in findings]
        assert "mysql-version-eol" in rule_ids
        f = next(f for f in findings if f.rule_id == "mysql-version-eol")
        assert f.cwe == "CWE-1104"
        assert "5.7.40" in f.evidence

    def test_mysql_56_eol(self):
        results = {
            "bind_address": ("10.0.1.5",),
            "require_secure_transport": (1,),
            "have_ssl": ("have_ssl", "YES"),
            "local_infile": (0,),
            "VERSION()": ("5.6.50",),
        }
        with _patch_env(), _patch_pymysql(results):
            findings = _check_mysql_deep(_svc())
        rule_ids = [f.rule_id for f in findings]
        assert "mysql-version-eol" in rule_ids

    def test_mysql_80_supported_no_finding(self):
        results = {
            "bind_address": ("10.0.1.5",),
            "require_secure_transport": (1,),
            "have_ssl": ("have_ssl", "YES"),
            "local_infile": (0,),
            "VERSION()": ("8.0.46",),
        }
        with _patch_env(), _patch_pymysql(results):
            findings = _check_mysql_deep(_svc())
        rule_ids = [f.rule_id for f in findings]
        assert "mysql-version-eol" not in rule_ids


# ---------------------------------------------------------------------------
# Lab scenario — vulnerable-lab target-db ground truth
# ---------------------------------------------------------------------------


class TestVulnerableLabGroundTruth:
    def test_full_lab_findings_match_ground_truth(self):
        """target-db tiene bind 0.0.0.0 + sin require_secure_transport +
        local_infile=1. Esperamos 3 findings deterministicos.
        """
        results = {
            "bind_address": ("0.0.0.0",),
            "require_secure_transport": (0,),
            "have_ssl": ("have_ssl", "YES"),
            "local_infile": (1,),
            "VERSION()": ("8.0.46",),
        }
        with _patch_env(), _patch_pymysql(results):
            findings = _check_mysql_deep(_svc(port=33060))
        rule_ids = {f.rule_id for f in findings}
        assert "mysql-bind-public" in rule_ids
        assert "mysql-tls-not-required" in rule_ids
        assert "mysql-local-infile-enabled" in rule_ids
        # MySQL 8.0.46 is current — no version-eol finding
        assert "mysql-version-eol" not in rule_ids
        assert len(findings) == 3
