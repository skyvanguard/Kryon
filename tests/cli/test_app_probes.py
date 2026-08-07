"""Batch F — dev/admin/big-data app-UI probes (Jenkins, Grafana, Kibana,
Prometheus, Hadoop YARN, Spark). Graceful-on-unreachable + signature precision
via a mocked _http_get.
"""

from __future__ import annotations

import kryon.cli.app_probes as ap
from kryon.cli.app_probes import _APP_PROBES, run_app_probes
from kryon.cli.engage import DiscoveredService

_DEAD = "127.0.0.1"


def _svc(port: int, host: str = _DEAD) -> DiscoveredService:
    return DiscoveredService(host=host, port=port, state="open", service="http")


def test_run_app_probes_graceful_on_closed_port():
    out = run_app_probes(_svc(8080), "http")
    assert isinstance(out, list)  # never raises against a dead port


def test_run_app_probes_never_raises_on_any_port():
    for port in (8080, 8443, 3000, 5601, 9090, 8088, 4040):
        assert isinstance(run_app_probes(_svc(port), "http"), list)


def _mock_http(monkeypatch, responses: dict[str, tuple[int, str]]):
    """Patch _http_get to return canned (status, body) keyed by path; None otherwise."""
    monkeypatch.setattr(ap, "_http_get", lambda host, port, path, scheme="http", **kw: responses.get(path))


def test_jenkins_script_console_is_critical(monkeypatch):
    _mock_http(monkeypatch, {
        "/api/json": (200, '{"_class":"hudson.model.Hudson","jobs":[]}'),
        "/script": (200, "<h1>Script Console</h1> groovy"),
    })
    f = ap._check_jenkins(_svc(8080), "http")
    assert f is not None and f.severity == "CRITICAL" and f.rule_id == "jenkins-script-console"


def test_jenkins_anonymous_read_is_high(monkeypatch):
    _mock_http(monkeypatch, {"/api/json": (200, '{"_class":"hudson.model.Hudson","jobs":[]}')})
    f = ap._check_jenkins(_svc(8080), "http")
    assert f is not None and f.severity == "HIGH" and f.rule_id == "jenkins-anonymous"


def test_jenkins_absent_returns_none(monkeypatch):
    _mock_http(monkeypatch, {"/api/json": (404, "nope"), "/": (200, "<html>not jenkins</html>")})
    assert ap._check_jenkins(_svc(8080), "http") is None


def test_grafana_anonymous_access(monkeypatch):
    _mock_http(monkeypatch, {
        "/api/health": (200, '{"database":"ok","version":"10.0.0"}'),
        "/api/search": (200, "[]"),
    })
    f = ap._check_grafana(_svc(3000), "http")
    assert f is not None and f.rule_id == "grafana-anonymous" and f.severity == "HIGH"


def test_grafana_exposed_but_authed(monkeypatch):
    _mock_http(monkeypatch, {
        "/api/health": (200, '{"database":"ok","version":"10.0.0"}'),
        "/api/search": (401, "unauthorized"),
    })
    f = ap._check_grafana(_svc(3000), "http")
    assert f is not None and f.rule_id == "grafana-exposed" and f.severity == "LOW"


def test_kibana_open(monkeypatch):
    _mock_http(monkeypatch, {"/api/status": (200, '{"name":"kibana","version":{"number":"8.0.0"}}')})
    f = ap._check_kibana(_svc(5601), "http")
    assert f is not None and f.rule_id == "kibana-open"


def test_prometheus_open(monkeypatch):
    _mock_http(monkeypatch, {"/api/v1/status/buildinfo": (200, '{"status":"success","data":{"version":"2.45"}}')})
    f = ap._check_prometheus(_svc(9090), "http")
    assert f is not None and f.rule_id == "prometheus-open"


def test_hadoop_yarn_unauth_is_critical(monkeypatch):
    _mock_http(monkeypatch, {"/ws/v1/cluster/info": (200, '{"clusterInfo":{"id":123,"state":"STARTED"}}')})
    f = ap._check_hadoop_yarn(_svc(8088), "http")
    assert f is not None and f.severity == "CRITICAL" and f.rule_id == "hadoop-yarn-unauth"


def test_spark_master_open_is_critical(monkeypatch):
    _mock_http(monkeypatch, {"/json/": (200, '{"workers":[],"sparkVersion":"3.5.0"}')})
    f = ap._check_spark(_svc(8080), "http")
    assert f is not None and f.severity == "CRITICAL" and f.rule_id == "spark-master-open"


def test_no_false_positive_on_generic_200(monkeypatch):
    _mock_http(monkeypatch, {p: (200, "<html>welcome</html>") for p in (
        "/api/json", "/", "/api/health", "/api/status", "/api/v1/status/buildinfo",
        "/-/healthy", "/ws/v1/cluster/info", "/json/")})
    for port in (8080, 3000, 5601, 9090, 8088):
        assert run_app_probes(_svc(port), "http") == []


def test_dispatch_table_well_formed():
    assert len(_APP_PROBES) == 6
    for matches, probe in _APP_PROBES:
        assert callable(matches) and callable(probe)
