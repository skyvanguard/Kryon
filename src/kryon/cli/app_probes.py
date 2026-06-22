"""Deterministic detectors for exposed dev / admin / big-data web UIs — Jenkins,
Grafana, Kibana, Prometheus, Hadoop YARN, Spark. These are among the most common
"oh, that's open" findings in real (especially cloud/internal) networks, and several
allow UNAUTHENTICATED RCE (Jenkins script console, Hadoop YARN app-submit, Spark).

HTTP probes, READ-ONLY, graceful. Imports utilities from service_probes (one-way;
engage imports the probe modules lazily, so no cycle).
"""

from __future__ import annotations

from kryon.cli.engage import DiscoveredService, Finding
from kryon.cli.service_probes import _f, _http_get, run_table


def _check_jenkins(svc: DiscoveredService, scheme: str) -> Finding | None:
    api = _http_get(svc.host, svc.port, "/api/json", scheme=scheme)
    is_jenkins = api and api[0] == 200 and '"_class"' in api[1] and ("hudson" in api[1] or "jenkins" in api[1].lower())
    if not is_jenkins:
        root = _http_get(svc.host, svc.port, "/", scheme=scheme)
        is_jenkins = root and "Jenkins" in (root[1] or "") and "Dashboard" in (root[1] or "")
        if not is_jenkins:
            return None
    # Anonymous read confirmed (api/json 200). Check the Groovy script console = RCE.
    script = _http_get(svc.host, svc.port, "/script", scheme=scheme)
    if script and script[0] == 200 and ("groovy" in script[1].lower() or "Script Console" in script[1]):
        return _f(svc, "CWE-306", "CRITICAL", "jenkins-script-console",
                  f"Jenkins con Script Console (Groovy) accesible SIN auth en {svc.host}:{svc.port} — RCE.",
                  "GET /script → 200 (consola Groovy = ejecución de código arbitrario en el master)",
                  "Habilitar 'Enable security' + matrix auth; bloquear /script; actualizar Jenkins.")
    return _f(svc, "CWE-306", "HIGH", "jenkins-anonymous",
              f"Jenkins con acceso anónimo de lectura en {svc.host}:{svc.port}.",
              "GET /api/json → 200 sin auth (jobs, builds, config visibles)",
              "Activar 'Enable security' + autorización (matrix/RBAC); no exponer a internet.")


def _check_grafana(svc: DiscoveredService, scheme: str) -> Finding | None:
    h = _http_get(svc.host, svc.port, "/api/health", scheme=scheme)
    if not (h and h[0] == 200 and '"database"' in h[1]):
        return None
    # Grafana confirmed. Anonymous access enabled? /api/search returns 200 (not 401).
    s = _http_get(svc.host, svc.port, "/api/search", scheme=scheme)
    if s and s[0] == 200:
        return _f(svc, "CWE-306", "HIGH", "grafana-anonymous",
                  f"Grafana con acceso anónimo habilitado en {svc.host}:{svc.port}.",
                  "GET /api/search → 200 sin auth (dashboards visibles)",
                  "Deshabilitar anonymous auth (auth.anonymous enabled=false); revisar default admin:admin.")
    return _f(svc, "CWE-1392", "LOW", "grafana-exposed",
              f"Grafana expuesto en {svc.host}:{svc.port} — revisar credenciales por defecto admin:admin.",
              "GET /api/health → 200", "Cambiar la contraseña del admin; restringir a red interna/VPN.")


def _check_kibana(svc: DiscoveredService, scheme: str) -> Finding | None:
    r = _http_get(svc.host, svc.port, "/api/status", scheme=scheme)
    if r and r[0] == 200 and ('"kibana"' in r[1] or '"version"' in r[1] and "number" in r[1]):
        return _f(svc, "CWE-306", "HIGH", "kibana-open",
                  f"Kibana accesible SIN auth en {svc.host}:{svc.port}.",
                  "GET /api/status → 200 con estado/versión (acceso a los índices de Elasticsearch vía Kibana)",
                  "Habilitar security (xpack/opensearch) + auth; no exponer 5601 a internet.")
    return None


def _check_prometheus(svc: DiscoveredService, scheme: str) -> Finding | None:
    r = _http_get(svc.host, svc.port, "/api/v1/status/buildinfo", scheme=scheme)
    if not (r and r[0] == 200 and '"version"' in r[1]):
        r = _http_get(svc.host, svc.port, "/-/healthy", scheme=scheme)
        if not (r and r[0] == 200 and "Healthy" in r[1]):
            return None
    return _f(svc, "CWE-306", "MEDIUM", "prometheus-open",
              f"Prometheus expuesto SIN auth en {svc.host}:{svc.port}.",
              "GET /api/v1/status/buildinfo → 200 (métricas + targets + config internos accesibles)",
              "Poner Prometheus detrás de un reverse-proxy con auth; restringir a red interna.")


def _check_hadoop_yarn(svc: DiscoveredService, scheme: str) -> Finding | None:
    r = _http_get(svc.host, svc.port, "/ws/v1/cluster/info", scheme=scheme)
    if r and r[0] == 200 and '"clusterInfo"' in r[1]:
        return _f(svc, "CWE-306", "CRITICAL", "hadoop-yarn-unauth",
                  f"Hadoop YARN ResourceManager SIN auth en {svc.host}:{svc.port} — RCE vía submit de aplicación.",
                  "GET /ws/v1/cluster/info → 200 (la REST API permite lanzar apps = ejecución de comandos en el cluster)",
                  "Habilitar Kerberos (security) + ACLs en YARN; nunca exponer 8088 a internet.")
    return None


def _check_spark(svc: DiscoveredService, scheme: str) -> Finding | None:
    r = _http_get(svc.host, svc.port, "/json/", scheme=scheme)
    if r and r[0] == 200 and ('"workers"' in r[1] or '"activeapps"' in r[1] or '"sparkVersion"' in r[1]):
        return _f(svc, "CWE-306", "CRITICAL", "spark-master-open",
                  f"Spark Master UI/API SIN auth en {svc.host}:{svc.port} — RCE vía submit de job.",
                  "GET /json/ → 200 con estado del cluster (REST submit habilita ejecución de código)",
                  "Habilitar auth (spark.authenticate) + ACLs; restringir el master a red interna.")
    return None


# Port → app-UI detectors. Several apps share 8080, so each verifies its own signature.
_APP_PROBES = (
    (lambda s: s.port in (8080, 8443, 50000), _check_jenkins),
    (lambda s: s.port in (8080, 8081, 4040, 6066), _check_spark),
    (lambda s: s.port == 8088, _check_hadoop_yarn),
    (lambda s: s.port == 3000, _check_grafana),
    (lambda s: s.port == 5601, _check_kibana),
    (lambda s: s.port in (9090, 9091), _check_prometheus),
)


def run_app_probes(svc: DiscoveredService, scheme: str = "http") -> list[Finding]:
    """Run matching dev/admin app-UI probes against an HTTP(S) service. Never raises."""
    return run_table(svc, _APP_PROBES, scheme)
