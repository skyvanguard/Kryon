"""Batch Q — application-layer web probes (Laravel Ignition, Spring actuator
tier-2, config leaks, ELMAH/trace.axd, GraphQL introspection, CORS, app consoles).
HTTP mocked; structural-signature precision + FP-safety checked."""

from __future__ import annotations

import kryon.cli.webapp_probes as wa
from kryon.cli.engage import DiscoveredService
from kryon.cli.webapp_probes import run_webapp_probes

_DEAD = "127.0.0.1"


def _svc(port: int = 80) -> DiscoveredService:
    return DiscoveredService(host=_DEAD, port=port, state="open", service="http")


def _mock_get(monkeypatch, responses):
    monkeypatch.setattr(wa, "_http_get", lambda host, port, path, scheme="http", **k: responses.get(path))


def test_run_webapp_probes_graceful(monkeypatch):
    monkeypatch.setattr(wa, "_http_get", lambda *a, **k: None)
    monkeypatch.setattr(wa, "_post", lambda *a, **k: None)
    monkeypatch.setattr(wa, "_cors_headers", lambda *a, **k: None)
    assert run_webapp_probes(_svc(), "http") == []


def test_laravel_ignition_rce(monkeypatch):
    _mock_get(monkeypatch, {"/_ignition/health-check": (200, '{"can_execute_commands":true}')})
    f = wa._check_laravel_ignition(_svc(), "http")
    assert f is not None and f.rule_id == "laravel-ignition-rce" and f.severity == "CRITICAL"


def test_laravel_ignition_safe_returns_none(monkeypatch):
    _mock_get(monkeypatch, {"/_ignition/health-check": (200, '{"can_execute_commands":false}')})
    assert wa._check_laravel_ignition(_svc(), "http") is None


def test_spring_jolokia_and_gateway(monkeypatch):
    _mock_get(monkeypatch, {
        "/actuator/jolokia": (200, '{"agent":"1.6","protocol":"7.2"}'),
        "/actuator/gateway/routes": (200, '[{"route_id":"x","predicate":"y"}]'),
    })
    rules = {f.rule_id for f in wa._check_spring_actuator2(_svc(), "http")}
    assert "spring-actuator-jolokia" in rules and "spring-actuator-gateway" in rules


def test_config_file_exposed(monkeypatch):
    _mock_get(monkeypatch, {"/application.properties": (200, "spring.datasource.password=s3cr3t\nspring.datasource.url=jdbc")})
    out = wa._check_config_files(_svc(), "http")
    assert out and out[0].rule_id == "app-config-exposed" and out[0].severity == "HIGH"


def test_config_file_html_catchall_no_fp(monkeypatch):
    _mock_get(monkeypatch, {p: (200, "<!doctype html><html>app</html>") for p, _ in wa._CONFIG_FILES})
    assert wa._check_config_files(_svc(), "http") == []


def test_elmah_and_trace(monkeypatch):
    _mock_get(monkeypatch, {
        "/elmah.axd": (200, "<title>Error log for app</title>"),
        "/trace.axd": (200, "Application Trace ... Request Details ..."),
    })
    rules = {f.rule_id for f in wa._check_dotnet_handlers(_svc(), "http")}
    assert rules == {"elmah-exposed", "aspnet-trace-axd"}


def test_graphql_introspection(monkeypatch):
    monkeypatch.setattr(wa, "_post", lambda host, port, path, scheme, body, **k:
                        (200, '{"data":{"__schema":{"queryType":{"name":"Query"}}}}') if path == "/graphql" else None)
    assert wa._check_graphql(_svc(), "http").rule_id == "graphql-introspection"


def test_graphql_disabled_returns_none(monkeypatch):
    monkeypatch.setattr(wa, "_post", lambda *a, **k: (400, '{"errors":[{"message":"introspection disabled"}]}'))
    assert wa._check_graphql(_svc(), "http") is None


def test_cors_reflected_credentials(monkeypatch):
    monkeypatch.setattr(wa, "_cors_headers", lambda host, port, scheme, origin: {
        "access-control-allow-origin": origin, "access-control-allow-credentials": "true"})
    assert wa._check_cors(_svc(), "http").rule_id == "cors-reflected-credentials"


def test_cors_wildcard_no_fp(monkeypatch):
    monkeypatch.setattr(wa, "_cors_headers", lambda host, port, scheme, origin: {
        "access-control-allow-origin": "*", "access-control-allow-credentials": "true"})
    assert wa._check_cors(_svc(), "http") is None


def test_tomcat_manager_realm(monkeypatch):
    _mock_get(monkeypatch, {"/manager/html": (401, 'realm="Tomcat Manager Application"')})
    rules = {f.rule_id for f in wa._check_app_consoles(_svc(), "http")}
    assert "tomcat-manager-exposed" in rules


def test_weblogic_console(monkeypatch):
    _mock_get(monkeypatch, {"/console/login/LoginForm.jsp": (200, "Oracle WebLogic Server Administration Console")})
    rules = {f.rule_id for f in wa._check_app_consoles(_svc(), "http")}
    assert "weblogic-console" in rules
