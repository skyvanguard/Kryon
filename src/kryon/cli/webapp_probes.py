"""Batch Q — application-layer web exposures with FP-safe structural signatures:
Laravel Ignition RCE, Spring Actuator tier-2 (jolokia/gateway/threaddump/mappings),
leaked app config files, ASP.NET ELMAH/trace.axd, GraphQL introspection, CORS
reflected-origin+credentials, and exposed admin consoles (Tomcat/JBoss/WebLogic).

READ-ONLY GET/POST of well-known paths; every match requires a STRUCTURAL signature
(a JSON key, a handler title, a credential pattern) so a SPA that 200s every path
can't false-trigger. Never sends an exploit payload — only the probe that confirms.
Imports _f + _http_get from service_probes (one-way; no import cycle).
"""

from __future__ import annotations

from kryon.cli.engage import DiscoveredService, Finding
from kryon.cli.service_probes import _f, _http_get, run_table

_T = 5.0


def _post(host: str, port: int, path: str, scheme: str, body: bytes, ctype: str = "application/json") -> tuple[int, str] | None:
    from kryon.cli.probe_http import request  # noqa: PLC0415

    r = request(host, port, path, scheme=scheme, method="POST", data=body,
                headers={"Content-Type": ctype}, timeout=_T)
    return (r.status, r.body) if r else None


def _cors_headers(host: str, port: int, scheme: str, origin: str) -> dict[str, str] | None:
    from kryon.cli.probe_http import request  # noqa: PLC0415

    r = request(host, port, "/", scheme=scheme, headers={"Origin": origin}, timeout=_T)
    return r.headers if r else None


def _check_laravel_ignition(svc: DiscoveredService, scheme: str) -> Finding | None:
    r = _http_get(svc.host, svc.port, "/_ignition/health-check", scheme=scheme)
    if r and r[0] == 200 and '"can_execute_commands":true' in r[1].replace(" ", ""):
        return _f(svc, "CWE-94", "CRITICAL", "laravel-ignition-rce",
                  f"Laravel Ignition con debug habilitado en {svc.host}:{svc.port} — RCE no autenticada (CVE-2021-3129).",
                  "GET /_ignition/health-check → can_execute_commands:true",
                  "Poner APP_DEBUG=false en producción; actualizar facade/ignition; bloquear /_ignition.")
    return None


_ACTUATORS = (
    ("/actuator/jolokia", lambda b: '"agent"' in b and '"protocol"' in b, "spring-actuator-jolokia",
     "CWE-94", "HIGH", "Jolokia (JMX over HTTP) — superficie de RCE vía MBeans"),
    ("/actuator/gateway/routes", lambda b: b.lstrip().startswith("[") or '"route_id"' in b or '"predicate"' in b,
     "spring-actuator-gateway", "CWE-94", "HIGH", "Spring Cloud Gateway actuator (CVE-2022-22947 SpEL RCE)"),
    ("/actuator/threaddump", lambda b: '"threads"' in b and '"threadName"' in b, "spring-actuator-threaddump",
     "CWE-200", "MEDIUM", "threaddump — stacks/estado interno de la JVM"),
    ("/actuator/mappings", lambda b: '"dispatcherServlet"' in b or '"dispatcherServlets"' in b, "spring-actuator-mappings",
     "CWE-200", "MEDIUM", "mappings — rutas internas de la aplicación"),
)


def _check_spring_actuator2(svc: DiscoveredService, scheme: str) -> list[Finding]:
    out: list[Finding] = []
    for path, sig, rule, cwe, sev, label in _ACTUATORS:
        r = _http_get(svc.host, svc.port, path, scheme=scheme)
        if r and r[0] == 200 and sig(r[1]):
            out.append(_f(svc, cwe, sev, rule,
                          f"Spring Actuator expuesto en {svc.host}:{svc.port}{path} — {label}.",
                          f"GET {path} → 200 con firma estructural del endpoint",
                          "Restringir /actuator a management.endpoints (auth); exponer solo /health/info."))
    return out


_CONFIG_FILES = (
    ("/application.properties", lambda b: "spring." in b and ("password" in b.lower() or "datasource" in b.lower())),
    ("/application.yml", lambda b: "datasource" in b.lower() or ("password:" in b.lower() and "spring" in b.lower())),
    ("/config/application.yml", lambda b: "datasource" in b.lower() or "password:" in b.lower()),
    ("/appsettings.json", lambda b: '"ConnectionStrings"' in b or '"connectionstrings"' in b.lower()),
    ("/wp-config.php.bak", lambda b: "DB_PASSWORD" in b and "define(" in b),
    ("/wp-config.php~", lambda b: "DB_PASSWORD" in b and "define(" in b),
    ("/.env.bak", lambda b: any(k in b for k in ("DB_PASSWORD", "APP_KEY", "SECRET")) and "<" not in b[:200]),
    ("/settings.py", lambda b: "SECRET_KEY" in b or "DATABASES" in b),
    ("/web.config", lambda b: "<connectionStrings" in b or "<configuration" in b),
)


def _check_config_files(svc: DiscoveredService, scheme: str) -> list[Finding]:
    out: list[Finding] = []
    for path, sig in _CONFIG_FILES:
        r = _http_get(svc.host, svc.port, path, scheme=scheme)
        if r and r[0] == 200 and sig(r[1]):
            out.append(_f(svc, "CWE-538", "HIGH", "app-config-exposed",
                          f"Archivo de configuración con credenciales expuesto en {svc.host}:{svc.port}{path}.",
                          f"GET {path} → 200 con patrón de credencial (DB/secret/connection string)",
                          "Mover la config fuera del docroot; bloquear estos paths en el server; rotar los secrets expuestos."))
    return out


_DOTNET_HANDLERS = (
    ("/elmah.axd", lambda b: "Error log for" in b or "Error Log for" in b, "elmah-exposed",
     "ELMAH — log de errores de la app (stack traces, queries, datos sensibles)"),
    ("/errorlog.axd", lambda b: "Error log for" in b or "Error Log for" in b, "elmah-exposed",
     "ELMAH — log de errores de la app"),
    ("/trace.axd", lambda b: "Application Trace" in b and "Request Details" in b, "aspnet-trace-axd",
     "ASP.NET trace.axd — trazas de requests (cookies, session, server vars)"),
)


def _check_dotnet_handlers(svc: DiscoveredService, scheme: str) -> list[Finding]:
    out: list[Finding] = []
    seen: set[str] = set()
    for path, sig, rule, label in _DOTNET_HANDLERS:
        if rule in seen:
            continue
        r = _http_get(svc.host, svc.port, path, scheme=scheme)
        if r and r[0] == 200 and sig(r[1]):
            seen.add(rule)
            out.append(_f(svc, "CWE-200", "HIGH", rule,
                          f"Handler de diagnóstico .NET expuesto en {svc.host}:{svc.port}{path} — {label}.",
                          f"GET {path} → handler renderizado (título exacto del módulo)",
                          "Deshabilitar ELMAH/trace en producción (web.config: trace enabled=false; ELMAH security)."))
    return out


_GRAPHQL_PATHS = ("/graphql", "/api/graphql", "/v1/graphql", "/graphql/v1", "/query")


def _check_graphql(svc: DiscoveredService, scheme: str) -> Finding | None:
    payload = b'{"query":"{__schema{queryType{name}}}"}'
    for path in _GRAPHQL_PATHS:
        r = _post(svc.host, svc.port, path, scheme, payload)
        if r and r[0] == 200 and '"__schema"' in r[1] and '"queryType"' in r[1]:
            return _f(svc, "CWE-200", "MEDIUM", "graphql-introspection",
                      f"GraphQL con introspección habilitada en {svc.host}:{svc.port}{path} — esquema completo expuesto.",
                      f"POST {path} {{__schema{{queryType{{name}}}}}} → respuesta con __schema",
                      "Deshabilitar introspección en producción; aplicar allowlist de queries / persisted queries.")
    return None


def _check_cors(svc: DiscoveredService, scheme: str) -> Finding | None:
    origin = "https://kryon-probe.example"
    h = _cors_headers(svc.host, svc.port, scheme, origin)
    if not h:
        return None
    acao = h.get("access-control-allow-origin", "")
    acac = h.get("access-control-allow-credentials", "").lower()
    if acao == origin and acac == "true":
        return _f(svc, "CWE-942", "HIGH", "cors-reflected-credentials",
                  f"CORS refleja cualquier Origin con credenciales en {svc.host}:{svc.port}.",
                  "Origin inyectado reflejado en Access-Control-Allow-Origin + Allow-Credentials: true",
                  "No reflejar el Origin; usar una allowlist estricta; nunca combinar ACAO dinámico con credentials.")
    return None


_CONSOLES = (
    ("/manager/html", lambda s, b: s == 401 or "Tomcat Manager" in b, "tomcat-manager-exposed", "MEDIUM",
     "Tomcat Manager — deploy de WARs (RCE con credenciales por defecto)"),
    ("/jmx-console/", lambda s, b: "JBoss" in b or "jmx-console" in b.lower(), "jboss-jmx-console", "HIGH",
     "JBoss JMX Console — invocación de MBeans (RCE)"),
    ("/console/login/LoginForm.jsp", lambda s, b: "WebLogic Server" in b or "WebLogic" in b, "weblogic-console", "HIGH",
     "Oracle WebLogic Admin Console (CVE-2020-14882 chain)"),
)


def _check_app_consoles(svc: DiscoveredService, scheme: str) -> list[Finding]:
    out: list[Finding] = []
    for path, sig, rule, sev, label in _CONSOLES:
        r = _http_get(svc.host, svc.port, path, scheme=scheme)
        if r and r[0] in (200, 401, 403) and sig(r[0], r[1]):
            out.append(_f(svc, "CWE-1188", sev, rule,
                          f"Consola de administración expuesta en {svc.host}:{svc.port}{path} — {label}.",
                          f"GET {path} → {r[0]} (firma/realm del producto)",
                          "Restringir la consola a la red de management; cambiar credenciales por defecto; parchear."))
    return out


_LIST_PROBES = (_check_spring_actuator2, _check_config_files, _check_dotnet_handlers, _check_app_consoles)
_SINGLE_PROBES = (_check_laravel_ignition, _check_graphql, _check_cors)


def run_webapp_probes(svc: DiscoveredService, scheme: str = "http") -> list[Finding]:
    """Application-layer web exposure probes. Never raises."""
    return run_table(svc, _LIST_PROBES + _SINGLE_PROBES, scheme)
