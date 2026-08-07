"""Canonical network-target parsing (single source of truth).

Port↔scheme maps, the web-port set, host extraction, CIDR / IP-literal checks —
each was reimplemented in 3-4 places (``repl/engine_phase``, ``cli/investigate``,
``services/target_orchestrator``, ``validation/target_guard``,
``skills/pre_hook_integration``) with real drift: divergent port maps, three
different web-port sets, ``split(":")`` vs ``rsplit(":")`` host extraction, and a
hand-rolled CIDR check that accepted ``/99``. Centralized here so all callers
agree.
"""

from __future__ import annotations

import ipaddress
from urllib.parse import urlparse

# Port → URL scheme. Canonical SUPERSET of the previously-divergent maps. Callers
# building a URL from a discovered service key off this.
PORT_TO_SCHEME: dict[int, str] = {
    22: "ssh", 2222: "ssh",
    3306: "mysql", 33060: "mysql",
    5432: "postgres", 27017: "mongo", 6379: "redis", 1433: "mssql", 1521: "oracle",
    53: "dns", 445: "smb", 139: "smb", 179: "bgp",
    80: "http", 8080: "http", 8000: "http", 8888: "http",
    443: "https", 8443: "https",
}  # fmt: skip

# Scheme → default port (the reverse direction some callers need).
SCHEME_TO_PORT: dict[str, int] = {
    "https": 443, "http": 80, "ssh": 22, "mysql": 3306, "postgres": 5432,
    "postgresql": 5432, "redis": 6379, "mongo": 27017, "mongodb": 27017,
    "dns": 53, "smb": 445, "cifs": 445, "bgp": 179,
}  # fmt: skip

# Ports treated as web (run the HTTP battery). Includes 3000/3003 (Juice Shop, a
# documented Kryon bench target) which the older inline sets dropped.
WEB_PORTS: frozenset[int] = frozenset({80, 443, 8080, 8443, 8000, 8888, 3000, 3003, 5000, 9000})


def bare_host(target: str, *, lower: bool = False) -> str:
    """Bare host from a URL/target (strips scheme, port, path). ``lower=True``
    for callers that compare against a lowercase set (e.g. the placeholder guard)."""
    t = (target or "").strip()
    if "://" in t:
        host = urlparse(t).hostname or ""
    else:
        host = t.split("/", 1)[0].split(":", 1)[0]
    host = host.strip()
    return host.lower() if lower else host


def is_cidr(target: str) -> bool:
    """True when `target` is a CIDR block (IPv4 or IPv6). Uses ``ipaddress`` so
    it correctly rejects a bad prefix (the old hand-rolled check accepted ``/99``)."""
    t = (target or "").strip()
    if "/" not in t:
        return False
    try:
        ipaddress.ip_network(t, strict=False)
        return True
    except ValueError:
        return False


def is_ip_literal(host: str) -> bool:
    """True when `host` is a literal IPv4/IPv6 address (not a hostname)."""
    try:
        ipaddress.ip_address((host or "").strip())
        return True
    except ValueError:
        return False


def scheme_for_service(port: int, service_name: str = "", web_ports: frozenset[int] = WEB_PORTS) -> str:
    """Best URL scheme for a discovered (port, service) — canonical map first,
    then a web/tls heuristic, else ``tcp``."""
    scheme = PORT_TO_SCHEME.get(port)
    if scheme is not None:
        return scheme
    name = (service_name or "").lower()
    if "http" in name or port in web_ports:
        return "https" if ("ssl" in name or "https" in name or port in (443, 8443)) else "http"
    return "tcp"
