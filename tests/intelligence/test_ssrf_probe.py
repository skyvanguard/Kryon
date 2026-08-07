"""Deterministic SSRF prober — find the param, confirm via file://, port-scan
internal. Models the live "creative"-style endpoint (POST body ``url=`` doing the
server-side fetch) the agent reached but couldn't systematize.
"""

from __future__ import annotations

from kryon.intelligence.ssrf_probe import (
    SsrfFinding,
    find_ssrf_param,
    probe_ssrf,
    scan_internal_ports,
)

PASSWD = "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"


def _make_fetcher(*, ssrf_param: str, ssrf_method: str, open_ports: set[int]):
    """Build a fetcher simulating an SSRF endpoint on ``ssrf_param``/``ssrf_method``.

    - file:///etc/passwd through the SSRF param leaks /etc/passwd.
    - http://127.0.0.1:<port> returns a banner for open ports, a refused error
      for closed ones. Any OTHER param is inert (no SSRF).
    """
    calls: list[tuple] = []

    def fetcher(method: str, url: str, params: dict) -> tuple[int, str]:
        calls.append((method, params))
        if method != ssrf_method or ssrf_param not in params:
            return 200, "<html>normal page, no fetch happened</html>"
        payload = params[ssrf_param]
        if payload.startswith("file://"):
            return 200, f"<pre>{PASSWD}</pre>"
        if payload.startswith("http://127.0.0.1:"):
            port = int(payload.split(":")[2].rstrip("/"))
            if port in open_ports:
                return 200, "<html><title>Internal Admin</title>" + "x" * 400 + "</html>"
            return 502, "Error: connection refused"  # closed baseline
        return 200, "fetched external"

    fetcher.calls = calls  # type: ignore[attr-defined]
    return fetcher


# ---------------------------------------------------------------------------
# Param discovery
# ---------------------------------------------------------------------------


def test_find_ssrf_param_post_url():
    fetcher = _make_fetcher(ssrf_param="url", ssrf_method="POST", open_ports=set())
    param, method, body = find_ssrf_param("http://beta.creative.thm/", fetcher=fetcher)
    assert param == "url"
    assert method == "POST"
    assert "root:x:" in body


def test_find_ssrf_param_get_uri():
    fetcher = _make_fetcher(ssrf_param="uri", ssrf_method="GET", open_ports=set())
    param, method, _ = find_ssrf_param("http://t/", fetcher=fetcher)
    assert (param, method) == ("uri", "GET")


def test_find_ssrf_param_none_when_inert():
    def inert(method, url, params):
        return 200, "<html>nothing fetched</html>"

    param, method, _ = find_ssrf_param("http://t/", fetcher=inert)
    assert param is None and method is None


def _make_http_only_fetcher(*, ssrf_param: str, ssrf_method: str, open_ports: set[int]):
    """Creative-style SSRF: file:// is blocked ("Dead"), only http:// fetches.
    Closed ports / file:// return "Dead"; open ports return the fetched page."""

    def fetcher(method: str, url: str, params: dict) -> tuple[int, str]:
        if method != ssrf_method or ssrf_param not in params:
            return 200, "<html><form>checker</form></html>"
        payload = params[ssrf_param]
        if payload.startswith("http://127.0.0.1:"):
            port = int(payload.split(":")[2].rstrip("/"))
            if port in open_ports:
                return 200, "<html><title>Fetched</title>" + "y" * 500 + "</html>"
        return 200, "<p> Dead </p>"  # file:// and closed ports

    return fetcher


def test_find_ssrf_param_http_only_no_file_read():
    # creative: POST url=, file:// blocked, 80 open internally → http-divergence path.
    fetcher = _make_http_only_fetcher(ssrf_param="url", ssrf_method="POST", open_ports={80})
    param, method, leaked = find_ssrf_param("http://beta.creative.thm/", fetcher=fetcher)
    assert (param, method) == ("url", "POST")
    assert leaked == ""  # confirmed via divergence, not file read


def test_probe_ssrf_http_only_emits_confirmed_and_ports():
    fetcher = _make_http_only_fetcher(ssrf_param="url", ssrf_method="POST", open_ports={80, 1337})
    res = probe_ssrf("http://beta.creative.thm/", fetcher=fetcher)
    assert res.param == "url" and res.method == "POST"
    kinds = {f.kind for f in res.findings}
    assert "confirmed" in kinds  # no file read → base confirmation finding
    assert "file_read" not in kinds
    ports = {f.port for f in res.findings if f.kind == "internal_port"}
    assert {80, 1337} <= ports


# ---------------------------------------------------------------------------
# Internal port scan
# ---------------------------------------------------------------------------


def test_scan_internal_ports_finds_open():
    fetcher = _make_fetcher(ssrf_param="url", ssrf_method="POST", open_ports={8080, 3000})
    found = scan_internal_ports("http://beta.creative.thm/", "url", "POST", fetcher=fetcher)
    assert 8080 in found and 3000 in found
    assert 22 not in found  # closed → refused → matches baseline


def test_scan_internal_ports_empty_when_all_closed():
    fetcher = _make_fetcher(ssrf_param="url", ssrf_method="POST", open_ports=set())
    assert scan_internal_ports("http://t/", "url", "POST", fetcher=fetcher) == []


# ---------------------------------------------------------------------------
# Full sweep
# ---------------------------------------------------------------------------


def test_probe_ssrf_full_flow():
    fetcher = _make_fetcher(ssrf_param="url", ssrf_method="POST", open_ports={1337})
    res = probe_ssrf("http://beta.creative.thm/", fetcher=fetcher)
    assert res.param == "url" and res.method == "POST"
    kinds = {(f.kind, f.port) for f in res.findings}
    assert ("file_read", 0) in kinds
    assert ("internal_port", 1337) in kinds
    # the file_read finding carries the leaked passwd as evidence
    fr = next(f for f in res.findings if f.kind == "file_read")
    assert "root:x:" in fr.evidence


def test_probe_ssrf_no_endpoint_returns_empty():
    def inert(method, url, params):
        return 404, "not found"

    res = probe_ssrf("http://t/", fetcher=inert)
    assert res.param is None
    assert res.findings == []


def test_finding_is_frozen():
    f = SsrfFinding(kind="internal_port", param="url", method="POST", port=8080)
    assert f.port == 8080
