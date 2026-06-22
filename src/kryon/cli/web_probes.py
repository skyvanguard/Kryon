"""Deterministic WEB findings — HTTP probes for exposed sensitive files, leaky
endpoints, and dangerous methods. URL-keyed (run once per HTTP service, checking
several paths), READ-ONLY, graceful. Complements the port-keyed service_probes.

These are among the most common real-world findings — an exposed ``/.git/`` or
``/.env`` is a full source/secret leak, yet nothing deterministic checked for them.
Each signature is specific enough that a catch-all 200 page won't false-trigger.
"""

from __future__ import annotations

from kryon.cli.engage import DiscoveredService, Finding
from kryon.cli.probe_base import DEFAULT_T as _T
from kryon.cli.service_probes import _f, _http_get


def _looks_html(body: str) -> bool:
    low = body[:600].lower()
    return "<html" in low or "<!doctype" in low or "<body" in low


# (path, rule_id, cwe, severity, body-signature predicate, label, remediation)
_SENSITIVE_FILES = (
    ("/.git/HEAD", "git-exposed", "CWE-538", "HIGH",
     lambda b: b.startswith("ref: refs/") or "refs/heads" in b[:120],
     ".git/ expuesto — el repositorio es dumpeable (código fuente + historial + secrets)",
     "Bloquear el acceso a /.git/ en el servidor web y removerlo del docroot."),
    ("/.svn/entries", "svn-exposed", "CWE-538", "MEDIUM",
     lambda b: b[:20].strip().isdigit() or "svn://" in b[:200] or "dir\n" in b[:50],
     ".svn/ expuesto — metadata del repositorio Subversion accesible",
     "Bloquear /.svn/ y remover del docroot."),
    ("/.env", "env-exposed", "CWE-538", "CRITICAL",
     lambda b: not _looks_html(b) and any(k in b for k in ("DB_", "APP_KEY", "SECRET", "PASSWORD", "API_KEY", "AWS_")),
     ".env expuesto — variables con credenciales (DB/API keys/secrets) en texto plano",
     "Mover .env fuera del docroot; bloquear dotfiles en el server (deny ^\\.)."),
    ("/server-status", "apache-server-status", "CWE-200", "MEDIUM",
     lambda b: "Apache Server Status" in b,
     "mod_status (/server-status) expuesto — requests en vivo, IPs, vhosts, paths internos",
     "Restringir /server-status a localhost (Require local) o deshabilitar mod_status."),
    ("/phpinfo.php", "phpinfo-exposed", "CWE-200", "MEDIUM",
     lambda b: "phpinfo()" in b or "PHP Version" in b,
     "phpinfo() expuesto — versión, módulos, paths, variables de entorno del server",
     "Remover phpinfo.php/info.php del docroot."),
    ("/actuator/env", "spring-actuator-env", "CWE-200", "HIGH",
     lambda b: '"propertySources"' in b or '"activeProfiles"' in b,
     "Spring Boot actuator /env expuesto — configuración + credenciales (datasource, keys)",
     "Restringir management.endpoints (exposure.include) + auth en el actuator."),
    ("/actuator/heapdump", "spring-actuator-heapdump", "CWE-200", "HIGH",
     lambda b: b[:4] == "\x1f\x8b\x08\x00" or "JAVA PROFILE" in b[:40] or "HPROF" in b[:40],
     "Spring Boot /actuator/heapdump descargable — dump de memoria con secrets en claro",
     "Deshabilitar el endpoint heapdump; nunca exponer actuator a internet."),
    ("/.DS_Store", "dsstore-exposed", "CWE-538", "LOW",
     lambda b: b[:4] == "\x00\x00\x00\x01" and "Bud1" in b[:16],
     ".DS_Store expuesto — enumera nombres de archivos del directorio",
     "Bloquear /.DS_Store; no subir archivos de macOS al docroot."),
    ("/.htpasswd", "htpasswd-exposed", "CWE-538", "HIGH",
     lambda b: not _looks_html(b) and ":" in b[:100] and any(h in b for h in ("$apr1$", "$2y$", "{SHA}", ":$1$")),
     ".htpasswd expuesto — hashes de credenciales HTTP Basic crackeables",
     "Bloquear archivos .ht* en el server (es el default de Apache, revisar nginx)."),
)

_BACKUPS = ("/config.php.bak", "/.env.bak", "/backup.sql", "/database.sql", "/web.config.bak", "/wp-config.php.bak")


def _extract_secrets(body: str, svc: DiscoveredService, path: str) -> list[Finding]:
    """Turn an exposed file's body into concrete secret findings (deterministic)."""
    from kryon.cli.secret_scanner import scan_secrets, to_findings  # noqa: PLC0415

    return to_findings(scan_secrets(body, path), svc.host, f"{path}")


def _check_sensitive_files(svc: DiscoveredService, scheme: str) -> list[Finding]:
    out: list[Finding] = []
    for path, rule, cwe, sev, sig, label, fix in _SENSITIVE_FILES:
        r = _http_get(svc.host, svc.port, path, scheme=scheme)
        if r and r[0] == 200 and r[1] and sig(r[1]):
            out.append(_f(svc, cwe, sev, rule, f"{label} ({scheme}://{svc.host}:{svc.port}{path}).",
                          f"GET {path} → 200 con contenido que matchea la firma", fix))
            out.extend(_extract_secrets(r[1], svc, path))  # extract the actual creds
    # Backup/source files — a 200 with non-HTML body is the signal.
    for path in _BACKUPS:
        r = _http_get(svc.host, svc.port, path, scheme=scheme)
        if r and r[0] == 200 and r[1] and not _looks_html(r[1]) and len(r[1]) > 20:
            out.append(_f(svc, "CWE-538", "HIGH", "backup-file-exposed",
                          f"Archivo de backup/fuente expuesto en {path}.",
                          f"GET {path} → 200 ({len(r[1])} bytes, no-HTML)",
                          "Remover backups del docroot; bloquear extensiones .bak/.old/.sql/~."))
            out.extend(_extract_secrets(r[1], svc, path))
            break  # one backup hit is enough signal
    return out


def _check_directory_listing(svc: DiscoveredService, scheme: str) -> Finding | None:
    r = _http_get(svc.host, svc.port, "/", scheme=scheme)
    if r and r[0] == 200 and "Index of /" in r[1] and "<a href=" in r[1]:
        return _f(svc, "CWE-548", "MEDIUM", "directory-listing",
                  f"Directory listing habilitado en {scheme}://{svc.host}:{svc.port}/.",
                  "GET / → 'Index of /' (autoindex de Apache/nginx)",
                  "Deshabilitar autoindex (Options -Indexes / autoindex off).")
    return None


def _check_http_trace(svc: DiscoveredService, scheme: str) -> Finding | None:
    """HTTP TRACE enabled = Cross-Site Tracing (XST) — echoes request incl. cookies."""
    from kryon.cli.probe_http import request  # noqa: PLC0415

    r = request(svc.host, svc.port, "/", scheme=scheme, method="TRACE", timeout=_T, max_body=400)
    if r and r.status == 200 and "TRACE /" in r.body:
        return _f(svc, "CWE-200", "LOW", "http-trace-enabled",
                  f"Método HTTP TRACE habilitado en {scheme}://{svc.host}:{svc.port} (XST).",
                  "TRACE / → 200 con el request reflejado",
                  "Deshabilitar TRACE (TraceEnable off / nginx: solo métodos permitidos).")
    return None


def _check_webdav(svc: DiscoveredService, scheme: str) -> Finding | None:
    """WebDAV / dangerous write methods advertised in the OPTIONS Allow header."""
    from kryon.cli.probe_http import request  # noqa: PLC0415

    r = request(svc.host, svc.port, "/", scheme=scheme, method="OPTIONS", timeout=_T)
    if r is None:
        return None
    allow = (r.headers.get("allow", "") + " " + r.headers.get("dav", "")).upper()
    dangerous = [m for m in ("PUT", "DELETE", "PROPFIND", "MKCOL", "COPY", "MOVE") if m in allow]
    if "PUT" in dangerous or "PROPFIND" in dangerous:
        return _f(svc, "CWE-650", "MEDIUM", "webdav-write-methods",
                  f"Métodos de escritura HTTP habilitados en {scheme}://{svc.host}:{svc.port}.",
                  f"OPTIONS → Allow: {', '.join(dangerous)} (WebDAV/PUT → posible upload de webshell)",
                  "Deshabilitar WebDAV/PUT/DELETE; permitir solo GET/POST/HEAD.")
    return None


_ADMIN_PANELS = (
    ("/phpmyadmin/", "phpMyAdmin", "phpmyadmin-exposed"),
    ("/adminer.php", "Adminer", "adminer-exposed"),
    ("/pma/", "phpMyAdmin", "phpmyadmin-exposed"),
)


def _check_admin_panels(svc: DiscoveredService, scheme: str) -> list[Finding]:
    out: list[Finding] = []
    for path, name, rule in _ADMIN_PANELS:
        r = _http_get(svc.host, svc.port, path, scheme=scheme)
        if r and r[0] == 200 and name.lower() in r[1].lower():
            out.append(_f(svc, "CWE-200", "MEDIUM", rule,
                          f"Panel de administración {name} expuesto en {path}.",
                          f"GET {path} → 200 con el login de {name}",
                          f"Restringir {name} a red interna/VPN + auth fuerte; mantenerlo parcheado."))
    return out




# API documentation surface — exposing the full API contract (every endpoint +
# params) to anonymous users is an information-disclosure / attack-surface finding.
_SWAGGER_PATHS = (
    "/swagger-ui.html", "/swagger-ui/index.html", "/v2/api-docs", "/v3/api-docs",
    "/openapi.json", "/swagger.json", "/api-docs",
)


def _check_swagger(svc: DiscoveredService, scheme: str) -> Finding | None:
    for path in _SWAGGER_PATHS:
        r = _http_get(svc.host, svc.port, path, scheme=scheme)
        if not (r and r[0] == 200):
            continue
        body = r[1] or ""
        is_spec = ('"swagger"' in body or '"openapi"' in body) and '"paths"' in body
        is_ui = "swagger-ui" in body.lower() or "Swagger UI" in body
        if is_spec or is_ui:
            return _f(svc, "CWE-200", "LOW", "swagger-exposed",
                      f"Documentación de API (Swagger/OpenAPI) expuesta en {svc.host}:{svc.port}{path}.",
                      f"GET {path} → 200 (contrato completo de la API: endpoints, params, modelos)",
                      "Restringir Swagger/OpenAPI a entornos no productivos o detrás de auth.")
    return None


def _check_wordpress(svc: DiscoveredService, scheme: str) -> list[Finding]:
    out: list[Finding] = []
    users = _http_get(svc.host, svc.port, "/wp-json/wp/v2/users", scheme=scheme)
    if users and users[0] == 200 and '"slug"' in (users[1] or "") and ('"name"' in users[1] or '"id"' in users[1]):
        out.append(_f(svc, "CWE-200", "MEDIUM", "wordpress-user-enum",
                      f"WordPress filtra el listado de usuarios vía REST API en {svc.host}:{svc.port}.",
                      "GET /wp-json/wp/v2/users → 200 con slugs/nombres (enumeración de usuarios para brute-force)",
                      "Bloquear /wp-json/wp/v2/users (plugin o regla del server); restringir la REST API."))
    xmlrpc = _http_get(svc.host, svc.port, "/xmlrpc.php", scheme=scheme)
    if xmlrpc and xmlrpc[0] in (200, 405) and "XML-RPC server accepts POST requests only" in (xmlrpc[1] or ""):
        out.append(_f(svc, "CWE-799", "MEDIUM", "wordpress-xmlrpc",
                      f"WordPress xmlrpc.php habilitado en {svc.host}:{svc.port} — amplificación de brute-force y pingback DDoS.",
                      "GET /xmlrpc.php → 'XML-RPC server accepts POST requests only' (system.multicall, pingback)",
                      "Deshabilitar xmlrpc.php si no se usa (regla del server o plugin)."))
    return out


def run_web_probes(svc: DiscoveredService, scheme: str = "http") -> list[Finding]:
    """Run every web probe against an HTTP(S) service. Never raises."""
    out: list[Finding] = []
    for fn in (_check_sensitive_files, _check_admin_panels, _check_wordpress):
        try:
            out.extend(fn(svc, scheme))
        except Exception:  # noqa: BLE001
            continue
    for fn in (_check_directory_listing, _check_http_trace, _check_webdav, _check_swagger):
        try:
            f = fn(svc, scheme)
            if f:
                out.append(f)
        except Exception:  # noqa: BLE001
            continue
    return out
