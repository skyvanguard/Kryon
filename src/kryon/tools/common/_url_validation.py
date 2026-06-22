"""URL validation helper — blocks SSRF against internal/metadata endpoints."""

from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlparse

# Cloud-metadata hostnames that resolve to a real IP but must never be fetched.
_METADATA_HOSTS = frozenset({"metadata.google.internal", "metadata.goog"})
_METADATA_IPS = frozenset({"169.254.169.254", "fd00:ec2::254", "100.100.100.200"})


def validate_external_url(url: str, *, allow_private: bool = False) -> str | None:
    """Validate that *url* is safe to fetch. Returns ``None`` if safe, or an error
    string describing why it was rejected.

    ``allow_private=True`` keeps the cloud-metadata / link-local / reserved / multicast
    blocks (the credential-theft + APIPA SSRF vectors, never a legit target) but PERMITS
    loopback + RFC-1918 private addresses — required for internal-network and CTF
    engagements where the legitimate target itself is private.
    """
    try:
        parsed = urlparse(url)
    except Exception:  # noqa: BLE001
        return "Malformed URL"

    if parsed.scheme not in ("http", "https"):
        return f"Unsupported scheme: {parsed.scheme}"

    hostname = parsed.hostname
    if not hostname:
        return "Missing hostname"
    if hostname.lower() in _METADATA_HOSTS:
        return "Cloud metadata endpoint blocked"

    # Resolve hostname to IP(s). A name that doesn't resolve is NOT an SSRF risk
    # (the fetch will simply fail), so don't block on it — only block when it
    # resolves to an internal/metadata IP.
    try:
        infos = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
    except socket.gaierror:
        return None

    for _family, _, _, _, sockaddr in infos:
        ip = ipaddress.ip_address(sockaddr[0])
        # Always blocked (no legit fetch target): cloud metadata + link-local (APIPA),
        # reserved, multicast.
        if str(ip) in _METADATA_IPS:
            return "Cloud metadata endpoint blocked"
        if ip.is_link_local:
            return f"Link-local address blocked: {ip}"
        if ip.is_reserved or ip.is_multicast:
            return f"Reserved/multicast address blocked: {ip}"
        # Loopback + private allowed only with the explicit opt-in (internal/CTF targets).
        if not allow_private:
            if ip.is_loopback:
                return f"Loopback address blocked: {ip}"
            if ip.is_private:
                return f"Private address blocked: {ip}"

    return None
