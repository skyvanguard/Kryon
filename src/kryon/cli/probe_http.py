"""Shared HTTP/TLS client for the deterministic probe layer. One place that
builds the (TLS-no-verify) context, the urllib opener, optional no-redirect
handling, Basic-auth, timing and body capture — replacing the five near-identical
implementations that had grown across the probe modules.

Pure stdlib (no kryon imports → no import cycle). The thin module-local helpers
(``_http_get``/``_vpn_get``/``_post``/``_cors_headers``/``_request``) now delegate
here while keeping their original names + return shapes, so every call site and
the tests that monkeypatch them stay valid.
"""

from __future__ import annotations

import base64
import time
import urllib.error
import urllib.request
from dataclasses import dataclass

_DEFAULT_T = 5.0


@dataclass(frozen=True)
class HttpResponse:
    status: int
    headers: dict[str, str]  # lowercased keys (last value wins on duplicates)
    cookies: str  # all Set-Cookie values joined + lowercased (multi-cookie safe)
    body: str
    elapsed: float


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001, D102
        return None  # don't follow → the 3xx surfaces as the response


def _https_ctx():
    import ssl  # noqa: PLC0415

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _pack(resp_headers, status: int, raw: bytes, elapsed: float) -> HttpResponse:
    items = list(resp_headers.items()) if resp_headers else []
    headers = {k.lower(): v for k, v in items}
    cookies = " ".join(v for k, v in items if k.lower() == "set-cookie").lower()
    return HttpResponse(status, headers, cookies, raw.decode("latin-1", "replace"), elapsed)


def request(
    host: str | None = None,
    port: int | None = None,
    path: str = "/",
    *,
    url: str | None = None,
    scheme: str = "http",
    method: str = "GET",
    headers: dict[str, str] | None = None,
    data: bytes | None = None,
    auth: str = "",
    follow_redirects: bool = True,
    timeout: float = _DEFAULT_T,
    max_body: int = 4000,
    user_agent: str = "kryon-probe",
) -> HttpResponse | None:
    """Issue one HTTP(S) request. Returns an ``HttpResponse`` (4xx/5xx surface as
    the response, not an exception) or ``None`` on a connection-level error."""
    full = url if url is not None else f"{scheme}://{host}:{port}{path}"
    hdrs = {"User-Agent": user_agent, **(headers or {})}
    if auth:
        hdrs["Authorization"] = "Basic " + base64.b64encode(auth.encode()).decode()
    is_https = full.lower().startswith("https://")
    opener_handlers: list = []
    if not follow_redirects:
        opener_handlers.append(_NoRedirect())
    if is_https:
        opener_handlers.append(urllib.request.HTTPSHandler(context=_https_ctx()))
    opener = urllib.request.build_opener(*opener_handlers)
    req = urllib.request.Request(full, data=data, headers=hdrs, method=method)
    t0 = time.monotonic()
    try:
        with opener.open(req, timeout=timeout) as r:  # noqa: S310 — fixed scheme, probe layer
            return _pack(r.headers, r.status, r.read(max_body), time.monotonic() - t0)
    except urllib.error.HTTPError as e:
        try:
            raw = e.read(max_body)
        except Exception:  # noqa: BLE001
            raw = b""
        return _pack(e.headers, e.code, raw, time.monotonic() - t0)
    except (OSError, ValueError):
        return None
