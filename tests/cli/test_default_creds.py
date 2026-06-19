"""Default-credential matrix + single-attempt Basic-auth tester (gated by KRYON_RED_TEAM)."""

from __future__ import annotations

import kryon.cli.default_creds as dc
from kryon.cli.engage import DiscoveredService


def _svc(port: int = 8080) -> DiscoveredService:
    return DiscoveredService(host="127.0.0.1", port=port, state="open", service="http")


def test_matrix_has_known_products():
    assert ("tomcat", "tomcat") in dc.DEFAULT_CRED_MATRIX["tomcat"]
    assert ("admin", "admin") in dc.DEFAULT_CRED_MATRIX["generic"]


def test_tomcat_advisory_in_banca_safe(monkeypatch):
    monkeypatch.delenv("KRYON_RED_TEAM", raising=False)
    monkeypatch.setattr(dc, "_http_get", lambda host, port, path, scheme="http", auth="": (401, "realm") if path == "/manager/html" and not auth else None)
    f = dc.check_tomcat_manager(_svc(), "http")
    assert f is not None and f.rule_id == "tomcat-manager-default-creds-advisory" and f.severity == "MEDIUM"


def test_tomcat_live_confirmation_under_red_team(monkeypatch):
    monkeypatch.setenv("KRYON_RED_TEAM", "true")

    def fake(host, port, path, scheme="http", auth=""):
        if path != "/manager/html":
            return None
        if not auth:
            return (401, "")
        return (200, "Tomcat Manager") if auth == "tomcat:tomcat" else (401, "")

    monkeypatch.setattr(dc, "_http_get", fake)
    f = dc.check_tomcat_manager(_svc(), "http")
    assert f is not None and f.rule_id == "tomcat-manager-default-creds" and f.severity == "CRITICAL"
    assert "tomcat:" in f.evidence and "tomcat:tomcat" not in f.evidence  # password redacted


def test_tomcat_wrong_creds_no_finding(monkeypatch):
    monkeypatch.setenv("KRYON_RED_TEAM", "true")
    monkeypatch.setattr(dc, "_http_get", lambda host, port, path, scheme="http", auth="": (401, "") if path == "/manager/html" else None)
    assert dc.check_tomcat_manager(_svc(), "http") is None


def test_tomcat_absent_returns_none(monkeypatch):
    monkeypatch.setattr(dc, "_http_get", lambda *a, **k: (404, ""))
    assert dc.check_tomcat_manager(_svc(), "http") is None


def test_basic_auth_defaults_only_under_red_team(monkeypatch):
    monkeypatch.delenv("KRYON_RED_TEAM", raising=False)
    monkeypatch.setattr(dc, "_http_get", lambda *a, **k: (401, ""))
    assert dc.check_basic_auth_defaults(_svc(), "http") is None  # banca-safe = no live test


def test_basic_auth_defaults_confirmed(monkeypatch):
    monkeypatch.setenv("KRYON_RED_TEAM", "1")

    def fake(host, port, path, scheme="http", auth=""):
        if path != "/":
            return None
        if not auth:
            return (401, "")
        return (200, "ok") if auth == "admin:admin" else (401, "")

    monkeypatch.setattr(dc, "_http_get", fake)
    f = dc.check_basic_auth_defaults(_svc(), "http")
    assert f is not None and f.rule_id == "http-default-creds"


def test_run_default_cred_checks_graceful(monkeypatch):
    monkeypatch.setattr(dc, "_http_get", lambda *a, **k: None)
    assert dc.run_default_cred_checks(_svc(), "http") == []
