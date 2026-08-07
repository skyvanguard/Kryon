"""Global HTTP header injection for authorized bug-bounty engagements.

Some VDP/BBP policies REQUIRE a research-identification header on ALL testing
traffic — e.g. HackerOne's ``X-HackerOne-Research: <alias>`` (Gogo VDP mandates
it). Set ``KRYON_HTTP_EXTRA_HEADERS`` and every HTTP tool wired to this helper
adds it, so your scans are distinguishable from malicious traffic and you stay
compliant (out-of-scope / unidentified traffic gets your IP banned and voids the
program's safe harbor).

Format — ``Name: Value`` pairs separated by ``||`` (NOT comma/semicolon, since a
header value can legitimately contain those)::

    KRYON_HTTP_EXTRA_HEADERS='X-HackerOne-Research: <your-h1-username>'
    KRYON_HTTP_EXTRA_HEADERS='X-HackerOne-Research: me || X-Bug-Bounty: true'
"""

from __future__ import annotations

import os

_ENV = "KRYON_HTTP_EXTRA_HEADERS"


def extra_http_headers() -> dict[str, str]:
    """Parse ``KRYON_HTTP_EXTRA_HEADERS`` into a ``{name: value}`` dict.

    Empty / unset env → ``{}`` (no-op, the default). Malformed fragments (no
    ``:``) are skipped rather than raising, so a typo can't crash a scan.
    """
    raw = os.environ.get(_ENV, "").strip()
    if not raw:
        return {}
    out: dict[str, str] = {}
    for part in raw.split("||"):
        part = part.strip()
        if ":" not in part:
            continue
        name, _, value = part.partition(":")
        name, value = name.strip(), value.strip()
        if name and value:
            out[name] = value
    return out


def header_lines() -> list[str]:
    """``["Name: Value", ...]`` — for CLI tools taking ``-H`` per header."""
    return [f"{name}: {value}" for name, value in extra_http_headers().items()]


def header_semicolon_string() -> str:
    """``"Name: Value; Name2: Value2"`` — for tools whose header arg is a single
    semicolon-joined string (e.g. Kryon's nuclei wrapper)."""
    return "; ".join(header_lines())
