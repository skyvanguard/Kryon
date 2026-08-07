"""Deterministic WEB findings — HTTP probes for exposed sensitive files, leaky
endpoints, and dangerous methods. URL-keyed (run once per HTTP service, checking
several paths), READ-ONLY, graceful. Complements the port-keyed service_probes.

These are among the most common real-world findings — an exposed ``/.git/`` or
``/.env`` is a full source/secret leak, yet nothing deterministic checked for them.
Each signature is specific enough that a catch-all 200 page won't false-trigger.
"""

from __future__ import annotations

import re as _re

from kryon.cli.engage import DiscoveredService, Finding
from kryon.cli.probe_base import DEFAULT_T as _T, _f, _http_get


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

_BACKUPS = (
    # config/db backups
    "/config.php.bak", "/.env.bak", "/backup.sql", "/database.sql", "/web.config.bak", "/wp-config.php.bak",
    "/config.php.old", "/config.php~",
    # page-source backups — Apache serves <page>.bak/.old/~/.save as plaintext source (CWE-530), the single
    # most common real-world source leak. THM Crypto Failures left index.php.bak leaking the whole auth flow
    # + ENC_SECRET_KEY, which the original config-only list missed entirely.
    "/index.php.bak", "/index.php.old", "/index.php~", "/index.php.save", "/index.bak", "/index.html.bak",
    "/login.php.bak", "/admin.php.bak",
    # full-site archives dropped in the docroot
    "/backup.zip", "/www.zip", "/site.zip", "/backup.tar.gz",
)


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


# WordPress is often served under a subpath, not the docroot (Internal: /blog). Probe the common
# bases and key off wp-content/wp-includes markers so the WP checks don't miss a subpath install.
_WP_BASES = ("", "/blog", "/wordpress", "/wp", "/cms", "/news", "/site")


def _find_wp_base(svc: DiscoveredService, scheme: str) -> str | None:
    """Return the URL subpath where WordPress lives (``""`` for docroot, ``/blog`` …) or None."""
    for base in _WP_BASES:
        r = _http_get(svc.host, svc.port, base + "/", scheme=scheme)
        if r and r[0] == 200 and r[1] and _re.search(r"wp-content|wp-includes|/wp-json|wp-login\.php", r[1], _re.I):
            return base
    return None


def _check_wordpress(svc: DiscoveredService, scheme: str) -> list[Finding]:
    out: list[Finding] = []
    base = _find_wp_base(svc, scheme)
    if base is None:
        return out
    label = base or "/"

    # Version from readme.html / the generator meta (feeds wpscan + version→CVE).
    ver = ""
    rd = _http_get(svc.host, svc.port, base + "/readme.html", scheme=scheme)
    if rd and rd[0] == 200 and rd[1]:
        m = _re.search(r"[Vv]ersion\s+(\d+\.\d+(?:\.\d+)?)", rd[1])
        ver = m.group(1) if m else ""
    out.append(_f(svc, "CWE-200", "LOW", "wordpress-detected",
                  f"WordPress detectado en {svc.host}:{svc.port}{label}{(' (v' + ver + ')') if ver else ''}.",
                  f"GET {label} → markers wp-content/wp-includes" + (f"; readme.html → v{ver}" if ver else ""),
                  "Mantener WordPress + plugins actualizados; `wpscan -e vp,u` para enumerar vulns/usuarios."))

    users = _http_get(svc.host, svc.port, base + "/wp-json/wp/v2/users", scheme=scheme)
    if users and users[0] == 200 and '"slug"' in (users[1] or "") and ('"name"' in users[1] or '"id"' in users[1]):
        out.append(_f(svc, "CWE-200", "MEDIUM", "wordpress-user-enum",
                      f"WordPress filtra el listado de usuarios vía REST API en {svc.host}:{svc.port}{label}.",
                      f"GET {label}/wp-json/wp/v2/users → 200 con slugs/nombres (enumeración para brute-force)",
                      "Bloquear /wp-json/wp/v2/users (plugin o regla del server); restringir la REST API."))
    xmlrpc = _http_get(svc.host, svc.port, base + "/xmlrpc.php", scheme=scheme)
    if xmlrpc and xmlrpc[0] in (200, 405) and "XML-RPC server accepts POST requests only" in (xmlrpc[1] or ""):
        out.append(_f(svc, "CWE-799", "MEDIUM", "wordpress-xmlrpc",
                      f"WordPress xmlrpc.php habilitado en {svc.host}:{svc.port}{label} — amplificación de brute-force y pingback DDoS.",
                      f"GET {label}/xmlrpc.php → 'XML-RPC server accepts POST requests only' (system.multicall, pingback)",
                      "Deshabilitar xmlrpc.php si no se usa (regla del server o plugin)."))
    return out


# CMS / app fingerprints via a public version-leaking path. Each: (path, name, regex, cve-note).
# The regex captures the version; the finding flags version disclosure + the product's headline CVE.
_CMS_FINGERPRINTS = (
    ("/CHANGELOG.txt", "Drupal", _re.compile(r"Drupal\s+(\d+\.\d+(?:\.\d+)?)", _re.I),
     "Drupalgeddon2 CVE-2018-7600 / SA-CORE-2019-003 si la versión es vieja"),
    ("/core/CHANGELOG.txt", "Drupal", _re.compile(r"Drupal\s+(\d+\.\d+(?:\.\d+)?)", _re.I),
     "Drupalgeddon2 CVE-2018-7600 / SA-CORE-2019-003 si la versión es vieja"),
    ("/administrator/manifests/files/joomla.xml", "Joomla",
     _re.compile(r"<version>\s*(\d+\.\d+(?:\.\d+)?)\s*</version>", _re.I),
     "CVE-2023-23752 (fuga de credenciales por API no autenticada) en 4.0.0–4.2.7"),
    ("/magento_version", "Magento", _re.compile(r"Magento/(\d+\.\d+(?:\.\d+)?)", _re.I),
     "CVE-2022-24086 (RCE pre-auth) / CosmicSting CVE-2024-34102 si no está parcheado"),
)


def _check_cms(svc: DiscoveredService, scheme: str) -> list[Finding]:
    """Fingerprint common CMS/apps by a public version-leaking path → version disclosure + CVE hint."""
    out: list[Finding] = []
    for path, name, rx, cve_note in _CMS_FINGERPRINTS:
        r = _http_get(svc.host, svc.port, path, scheme=scheme)
        if not r or r[0] != 200 or not r[1]:
            continue
        m = rx.search(r[1])
        if not m:
            continue
        ver = m.group(1)
        out.append(_f(
            svc, "CWE-200", "MEDIUM", f"{name.lower()}-version-disclosure",
            f"{name} {ver} identificado en {svc.host}:{svc.port} con su versión expuesta públicamente.",
            f"GET {path} → versión {name} {ver}. Verificar parches: {cve_note}.",
            f"Restringir/eliminar el archivo de versión público ({path}); mantener {name} en la última versión.",
        ))
        break  # one CMS identified per host is enough
    # Zabbix frontend (version is in the page, not a dedicated file).
    zb = _http_get(svc.host, svc.port, "/zabbix/index.php", scheme=scheme) or _http_get(
        svc.host, svc.port, "/index.php", scheme=scheme)
    if zb and zb[0] == 200 and zb[1] and "zabbix" in zb[1].lower() and ("sia" in zb[1].lower() or "z-logo" in zb[1].lower()):
        zm = _re.search(r"Zabbix\s+(\d+\.\d+(?:\.\d+)?)", zb[1])
        ver = zm.group(1) if zm else "(versión no expuesta)"
        out.append(_f(
            svc, "CWE-200", "MEDIUM", "zabbix-frontend-exposed",
            f"Frontend de Zabbix expuesto en {svc.host}:{svc.port} ({ver}).",
            f"GET /zabbix/index.php → login de Zabbix {ver}. Verificar CVE-2022-23131 (bypass SAML/sessionid).",
            "Restringir el frontend de Zabbix a redes internas/VPN; parchear; MFA en el login.",
        ))
    return out


def run_web_probes(svc: DiscoveredService, scheme: str = "http") -> list[Finding]:
    """Run every web probe against an HTTP(S) service. Never raises.

    Each sub-probe issues many sequential GETs to the SAME host — serially this
    dominated the deterministic phase (~35s on a live web host). The sub-probes
    are independent, so they run concurrently by default (I/O releases the GIL);
    ``KRYON_PROBE_SERIAL=1`` forces the old sequential order."""
    import os
    from concurrent.futures import ThreadPoolExecutor

    fns = (
        _check_sensitive_files,
        _check_admin_panels,
        _check_wordpress,
        _check_cms,
        _check_directory_listing,
        _check_http_trace,
        _check_webdav,
        _check_swagger,
    )

    def _run(fn) -> list:  # noqa: ANN001
        try:
            r = fn(svc, scheme)
        except Exception:  # noqa: BLE001 — one probe must never break the rest
            return []
        if not r:
            return []
        return r if isinstance(r, list) else [r]

    if os.environ.get("KRYON_PROBE_SERIAL", "").strip().lower() in ("1", "true", "yes", "on"):
        out: list[Finding] = []
        for fn in fns:
            out.extend(_run(fn))
        return out

    out = []
    with ThreadPoolExecutor(max_workers=len(fns)) as ex:
        for res in ex.map(_run, fns):
            out.extend(res)
    return out
