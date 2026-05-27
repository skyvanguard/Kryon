"""FASE 11.T — web common paths discovery pre_hook.

Probes a curated list of well-known web paths and reports which ones
return non-404 responses. Designed to break the Bench Robots failure
mode where the model never consulted ``/robots.txt`` even though the
lab hides flags behind disallow entries there. The output is injected
into the first reflection turn under ``web_common_paths`` so the
model has authoritative findings before its first reasoning step.

Paths probed (curated, ~14 paths, banca-safe — pure GET no payloads):
  /robots.txt, /sitemap.xml         — crawl hints (Robots THM key path)
  /.git/config, /.git/HEAD          — git exposure (real-world common)
  /.env, /.env.local                — config leak (web app default)
  /admin, /login                    — auth surface
  /api, /api/v1                     — API discovery
  /server-status                    — Apache mod_status exposure
  /swagger.json, /openapi.json      — API doc leak
  /wp-login.php                     — WordPress hint

Per-path timeout: 4s. Wall-clock cap via concurrent.futures with
ThreadPoolExecutor(max_workers=8). Total time ~5-10s typical.

The /robots.txt body is always rendered fully (up to 30 lines). The
``fact_extractor._DISALLOW_PATH_RE`` regex picks up ``Disallow:`` lines
from the reflection prompt, so the FASE 11.K-P planner rules (gobuster
on disallow paths, curl with vhost header) can fire on subsequent
turns.
"""

from __future__ import annotations

import concurrent.futures
import logging
import urllib.error
import urllib.request
from typing import Any

logger = logging.getLogger(__name__)

_COMMON_PATHS: tuple[str, ...] = (
    "/robots.txt",
    "/sitemap.xml",
    "/.git/config",
    "/.git/HEAD",
    "/.env",
    "/.env.local",
    "/admin",
    "/login",
    "/api",
    "/api/v1",
    "/server-status",
    "/swagger.json",
    "/openapi.json",
    "/wp-login.php",
)

_PER_PATH_TIMEOUT_S = 4.0
_MAX_BODY_PREVIEW = 800  # chars per path
_WALL_CLOCK_S = 22.0
_ROBOTS_BODY_MAX_LINES = 30


def _probe_path(base: str, path: str) -> tuple[str, int, int, str]:
    """Returns (path, status_code, body_size, body_preview).

    Status code -1 signals a transport-level error (DNS / refused /
    timeout). The error string lands in body_preview so we can surface
    it in the output without crashing the whole probe.
    """
    url = base + path
    req = urllib.request.Request(
        url,
        method="GET",
        headers={"User-Agent": "Kryon/web-paths-probe"},
    )
    try:
        with urllib.request.urlopen(req, timeout=_PER_PATH_TIMEOUT_S) as resp:
            body = resp.read(_MAX_BODY_PREVIEW)
            body_str = body.decode("utf-8", errors="replace")
            return (path, resp.status, len(body_str), body_str)
    except urllib.error.HTTPError as exc:
        # HTTPError IS a response — capture status and body.
        body_str = ""
        try:
            raw = exc.read(_MAX_BODY_PREVIEW)
            body_str = raw.decode("utf-8", errors="replace")
        except Exception:  # noqa: BLE001 — body may be unavailable
            pass
        return (path, exc.code, len(body_str), body_str)
    except Exception as exc:  # noqa: BLE001 — never crash the whole probe
        return (path, -1, 0, f"[error] {exc}")


def _interest_key(row: tuple[str, int, int, str]) -> tuple[int, int]:
    """Sort key that pushes interesting status codes to the top.

    200 > 3xx > 403 > 401 > other > 404 > errored.
    Within 200s, larger body is more interesting (real content vs
    placeholder).
    """
    _, status, size, _ = row
    if status == 200:
        return (0, -size)
    if status in (301, 302, 307, 308):
        return (1, 0)
    if status == 403:
        return (2, 0)
    if status == 401:
        return (3, 0)
    if status == 404:
        return (8, 0)
    if status == -1:
        return (9, 0)
    return (4, 0)


def run(ctx: dict[str, Any]) -> str:
    """Probe well-known paths against ``ctx['target']``.

    Returns a markdown-formatted summary. Empty / missing target
    yields a one-line skip message (not a crash). All transport
    errors are captured per-path; the probe never raises.
    """
    target = (ctx.get("target") or "").strip().rstrip("/")
    if not target:
        return "[web-common-paths] no target in ctx"

    # Operator may pass bare host:port — normalize to URL.
    if not (target.startswith("http://") or target.startswith("https://")):
        target = f"http://{target}"

    results: list[tuple[str, int, int, str]] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as ex:
        futures = {ex.submit(_probe_path, target, p): p for p in _COMMON_PATHS}
        try:
            for fut in concurrent.futures.as_completed(futures, timeout=_WALL_CLOCK_S):
                try:
                    results.append(fut.result())
                except Exception as exc:  # noqa: BLE001
                    path = futures[fut]
                    results.append((path, -1, 0, f"[error] {exc}"))
        except concurrent.futures.TimeoutError:
            # Capture whatever finished; the wall-clock budget bounds us.
            logger.debug("web_common_paths wall-clock hit at %ss", _WALL_CLOCK_S)

    results.sort(key=_interest_key)

    interesting = [r for r in results if r[1] not in (404, -1)]
    nonexistent = [r for r in results if r[1] == 404]
    errored = [r for r in results if r[1] == -1]

    lines: list[str] = [f"# Web common paths probe — {target}"]

    if not interesting:
        lines.append(
            f"No interesting paths discovered "
            f"(404: {len(nonexistent)}, errored: {len(errored)} of {len(_COMMON_PATHS)} probed)."
        )
        return "\n".join(lines)

    lines.append(f"## Interesting paths ({len(interesting)})")
    for path, status, size, body in interesting:
        lines.append(f"- [{status}] {path}  ({size} bytes)")
        if path == "/robots.txt" and body and body.strip():
            # Always inline /robots.txt — the disallow paths are the
            # entire point of this probe, and the fact_extractor
            # downstream depends on the literal ``Disallow:`` lines.
            lines.append("  ```")
            for body_line in body.splitlines()[:_ROBOTS_BODY_MAX_LINES]:
                lines.append(f"  {body_line}")
            lines.append("  ```")
        elif body and body.strip() and status == 200:
            preview = body[:200].replace("\n", " ").replace("\r", "")
            lines.append(f"  preview: {preview!r}")

    if nonexistent:
        joined = ", ".join(p for p, _, _, _ in nonexistent)
        lines.append(f"\n## Non-existent (404, {len(nonexistent)}): {joined}")

    if errored:
        joined = ", ".join(p for p, _, _, _ in errored)
        lines.append(f"\n## Errored (transport, {len(errored)}): {joined}")

    return "\n".join(lines)
