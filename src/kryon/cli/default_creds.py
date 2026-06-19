"""Deterministic default-credential matrix + a single-attempt HTTP-Basic tester.

The probe layer already fingerprints the product; this maps the product to the
credentials it ships with and (under KRYON_RED_TEAM only) confirms them with ONE
Basic-auth request — never a brute-force loop. In the banca-safe default it emits
an advisory ("known defaults X — verify"), since an auth attempt is an *active*
action; live confirmation is gated like the rest of the active stack.
"""

from __future__ import annotations

import os

from kryon.cli.engage import DiscoveredService, Finding, make_finding
from kryon.cli.service_probes import _http_get

# product key → list of (user, password) shipped/commonly-left defaults.
DEFAULT_CRED_MATRIX: dict[str, list[tuple[str, str]]] = {
    "tomcat": [("tomcat", "tomcat"), ("admin", "admin"), ("tomcat", "s3cret"),
               ("admin", "tomcat"), ("role1", "role1"), ("both", "tomcat")],
    "generic": [("admin", "admin"), ("admin", "password"), ("admin", ""), ("root", "root"),
                ("administrator", "administrator")],
    "grafana": [("admin", "admin")],
    "jenkins": [("admin", "admin")],
    "manageengine": [("admin", "admin")],
    "zabbix": [("Admin", "zabbix")],
    "nagios": [("nagiosadmin", "nagiosadmin")],
}

_ACTIVE = "KRYON_RED_TEAM"


def _red_team() -> bool:
    return os.environ.get(_ACTIVE, "").lower() in ("1", "true", "yes")


def _finding(svc: DiscoveredService, rule_id: str, sev: str, msg: str, evidence: str, fix: str) -> Finding:
    return make_finding("CWE-1392", sev, svc.host, rule_id, msg, evidence=evidence, remediation=fix)


def _test_basic(svc: DiscoveredService, scheme: str, path: str, creds: list[tuple[str, str]]) -> tuple[str, str] | None:
    """Return the first (user, pass) that authenticates (200) on a Basic-auth path."""
    for user, pw in creds:
        r = _http_get(svc.host, svc.port, path, scheme=scheme, auth=f"{user}:{pw}")
        if r and r[0] == 200:
            return user, pw
    return None


def check_tomcat_manager(svc: DiscoveredService, scheme: str) -> Finding | None:
    """Tomcat Manager: a default cred grants WAR deploy = RCE."""
    probe = _http_get(svc.host, svc.port, "/manager/html", scheme=scheme)
    if not (probe and probe[0] in (401, 403)):  # manager present + protected
        return None
    if not _red_team():
        return _finding(svc, "tomcat-manager-default-creds-advisory", "MEDIUM",
                        f"Tomcat Manager protegido en {svc.host}:{svc.port} — probar defaults (tomcat:tomcat, admin:admin).",
                        "GET /manager/html → 401/403 (defaults conocidos no testeados en modo banca-safe)",
                        "Cambiar las credenciales de tomcat-users.xml; restringir /manager a la red de management.")
    hit = _test_basic(svc, scheme, "/manager/html", DEFAULT_CRED_MATRIX["tomcat"])
    if hit:
        return _finding(svc, "tomcat-manager-default-creds", "CRITICAL",
                        f"Tomcat Manager con credenciales por defecto en {svc.host}:{svc.port} — RCE vía deploy de WAR.",
                        f"Login exitoso con {hit[0]}:{'*' * len(hit[1])} en /manager/html",
                        "Cambiar las credenciales de tomcat-users.xml YA; restringir /manager a la red de management.")
    return None


def check_basic_auth_defaults(svc: DiscoveredService, scheme: str) -> Finding | None:
    """Any Basic-auth-protected root that accepts a universal default cred."""
    root = _http_get(svc.host, svc.port, "/", scheme=scheme)
    if not (root and root[0] == 401):  # only meaningful when Basic-auth is enforced
        return None
    if not _red_team():
        return None  # advisory would be too noisy on every 401; only confirm under red-team
    hit = _test_basic(svc, scheme, "/", DEFAULT_CRED_MATRIX["generic"])
    if hit:
        return _finding(svc, "http-default-creds", "HIGH",
                        f"Endpoint con autenticación Basic y credenciales por defecto en {svc.host}:{svc.port}.",
                        f"Login exitoso con {hit[0]}:{'*' * len(hit[1])} en /",
                        "Cambiar las credenciales por defecto; aplicar contraseñas fuertes + rate-limiting.")
    return None


def run_default_cred_checks(svc: DiscoveredService, scheme: str = "http") -> list[Finding]:
    """Default-credential checks. Live confirmation gated by KRYON_RED_TEAM. Never raises."""
    out: list[Finding] = []
    for fn in (check_tomcat_manager, check_basic_auth_defaults):
        try:
            f = fn(svc, scheme)
            if f:
                out.append(f)
        except Exception:  # noqa: BLE001
            continue
    return out
