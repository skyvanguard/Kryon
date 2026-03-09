"""URL validation helper — blocks SSRF against internal/metadata endpoints."""

from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlparse


def validate_external_url(url: str) -> str | None:
    """Validate that *url* points to a public, external host.

    Returns ``None`` if the URL is safe, or an error string describing why
    the URL was rejected.
    """
    try:
        parsed = urlparse(url)
    except Exception:
        return "Malformed URL"

    if parsed.scheme not in ("http", "https"):
        return f"Unsupported scheme: {parsed.scheme}"

    hostname = parsed.hostname
    if not hostname:
        return "Missing hostname"

    # Resolve hostname to IP(s)
    try:
        infos = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
    except socket.gaierror:
        return f"Cannot resolve hostname: {hostname}"

    for family, _, _, _, sockaddr in infos:
        ip = ipaddress.ip_address(sockaddr[0])
        if ip.is_loopback:
            return f"Loopback address blocked: {ip}"
        if ip.is_private:
            return f"Private address blocked: {ip}"
        if ip.is_link_local:
            return f"Link-local address blocked: {ip}"
        if ip.is_reserved:
            return f"Reserved address blocked: {ip}"
        # Block cloud metadata endpoints (169.254.169.254)
        if str(ip) == "169.254.169.254":
            return "Cloud metadata endpoint blocked"

    return None
