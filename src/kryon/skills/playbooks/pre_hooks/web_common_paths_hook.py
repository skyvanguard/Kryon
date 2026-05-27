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
import re
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

logger = logging.getLogger(__name__)

# FASE 11.V — extract <form> + <input> field names from HTML body.
# Permissive regex (no HTML parsing dependency); covers the common
# shapes used by CTF login forms and real-world PHP apps.
_INPUT_NAME_RE = re.compile(r'<input[^>]*\bname\s*=\s*[\'"]([^\'"]+)[\'"]', re.IGNORECASE)
_FORM_ACTION_RE = re.compile(r'<form[^>]*\baction\s*=\s*[\'"]([^\'"]+)[\'"]', re.IGNORECASE)
_FORM_METHOD_RE = re.compile(r'<form[^>]*\bmethod\s*=\s*[\'"]([^\'"]+)[\'"]', re.IGNORECASE)

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

# FASE 11.U — sub-paths probed UNDER each Disallow path discovered
# in /robots.txt. Curated to cover the common assets behind a hidden
# directory on recon CTFs and real-world web servers: directory
# listing (trailing slash), default index files, auth surfaces, and
# common CMS / app entry points.
_DISALLOW_SUBPATHS: tuple[str, ...] = (
    "",            # the disallow path itself (directory listing)
    "/",           # with trailing slash (forces dir listing if mod_autoindex)
    "/index.php",
    "/index.html",
    "/login.php",
    "/admin.php",
    "/register.php",
    "/config.php",
    "/upload.php",
    "/dashboard.php",
)
_MAX_DISALLOW_PATHS_TO_ENUMERATE = 5

_PER_PATH_TIMEOUT_S = 12.0
_MAX_BODY_PREVIEW = 800  # chars per path
# FASE 11.T.3 — bumped further from 45s to 90s + per-path 6s → 12s.
# Bench Robots T.2 (concurrent with nuclei + over OpenVPN) showed even
# /robots.txt erroring out — only 185-char output came through with
# "All 14 probed paths returned 404 or errored". Network latency over
# VPN + concurrency starves urllib. 12s/path × 14 paths sequential
# would be 168s; with max_workers=8 concurrency, ~25s realistic.
_WALL_CLOCK_S = 90.0
_ROBOTS_BODY_MAX_LINES = 30


# FASE 11.U.2 — custom opener that captures 301/302 status WITHOUT
# following the redirect. The default urllib follows redirects which
# loses the original status code; against Robots THM, /harm/to/self
# returns 302 → robots.thm (external host) which then fails DNS,
# making the probe look like a transport error rather than a redirect.
# We want the 302 itself so the model knows the path EXISTS and is
# protected by a redirect (typical CMS auth gate).
class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D401
        return None  # do not follow


_NO_REDIRECT_OPENER = urllib.request.build_opener(_NoRedirectHandler())


def _probe_path(base: str, path: str) -> tuple[str, int, int, str]:
    """Returns (path, status_code, body_size, body_preview).

    Status code -1 signals a transport-level error (DNS / refused /
    timeout). The error string lands in body_preview so we can surface
    it in the output without crashing the whole probe.

    Redirects (301/302/307/308) are reported AS-IS — we do not follow.
    See ``_NoRedirectHandler`` for rationale (Robots THM bug).
    """
    url = base + path
    req = urllib.request.Request(
        url,
        method="GET",
        headers={"User-Agent": "Kryon/web-paths-probe"},
    )
    try:
        with _NO_REDIRECT_OPENER.open(req, timeout=_PER_PATH_TIMEOUT_S) as resp:
            body = resp.read(_MAX_BODY_PREVIEW)
            body_str = body.decode("utf-8", errors="replace")
            return (path, resp.status, len(body_str), body_str)
    except urllib.error.HTTPError as exc:
        # HTTPError IS a response — capture status and body.
        # FASE 11.U.2: 301/302/307/308 raise HTTPError when the
        # NoRedirectHandler returns None; we want to preserve their
        # Location header in the preview so the model knows where the
        # redirect points (often reveals the vhost or auth path).
        body_str = ""
        try:
            raw = exc.read(_MAX_BODY_PREVIEW)
            body_str = raw.decode("utf-8", errors="replace")
        except Exception:  # noqa: BLE001 — body may be unavailable
            pass
        # Append Location header for redirects (highly informative).
        if exc.code in (301, 302, 307, 308):
            location = exc.headers.get("Location", "")
            if location:
                body_str = f"[Location: {location}]\n{body_str}"
        return (path, exc.code, len(body_str), body_str)
    except Exception as exc:  # noqa: BLE001 — never crash the whole probe
        return (path, -1, 0, f"[error] {exc}")


def _extract_vhost_from_location(body_preview: str, target: str) -> str:
    """FASE 11.V — pull the vhost out of a redirect's Location header.

    Our ``_probe_path`` prepends ``[Location: http://host/path]\\n`` to
    the body when a redirect status was captured. We parse that line
    and return the host part IFF it differs from the target's host.
    Same-host redirects (e.g. /path → /path/) aren't vhost tricks; we
    only care when the server is steering us to a different name.
    """
    m = re.match(r"^\[Location:\s*([^\]]+)\]", body_preview)
    if not m:
        return ""
    location = m.group(1).strip()
    try:
        loc_host = urllib.parse.urlparse(location).hostname or ""
        target_host = urllib.parse.urlparse(target).hostname or ""
    except Exception:  # noqa: BLE001
        return ""
    if loc_host and loc_host.lower() != target_host.lower():
        return loc_host
    return ""


def _probe_with_vhost(target: str, path: str, vhost: str) -> tuple[int, int, str]:
    """FASE 11.V — GET ``target + path`` with ``Host: vhost`` header.

    Returns (status, body_size, body_preview). Used as the second
    probe in the vhost-trick scenario: the IP responds 302 →
    http://vhost/..., DNS doesn't resolve vhost, but the IP DOES
    serve the real content when given the right Host header.
    """
    req = urllib.request.Request(
        target + path,
        method="GET",
        headers={
            "User-Agent": "Kryon/web-paths-probe",
            "Host": vhost,
        },
    )
    try:
        with _NO_REDIRECT_OPENER.open(req, timeout=_PER_PATH_TIMEOUT_S) as resp:
            body = resp.read(_MAX_BODY_PREVIEW * 4)  # bigger body for form parsing
            body_str = body.decode("utf-8", errors="replace")
            return (resp.status, len(body_str), body_str)
    except urllib.error.HTTPError as exc:
        body_str = ""
        try:
            raw = exc.read(_MAX_BODY_PREVIEW * 4)
            body_str = raw.decode("utf-8", errors="replace")
        except Exception:  # noqa: BLE001
            pass
        return (exc.code, len(body_str), body_str)
    except Exception as exc:  # noqa: BLE001
        return (-1, 0, f"[error] {exc}")


def _detect_login_form(html: str) -> dict[str, Any]:
    """FASE 11.V — find <form> + <input name=...> in an HTML body.

    Returns ``{}`` when no form-shaped markup is found. Otherwise a
    dict with the form's action, method, and a list of input names.
    Used to flag login surfaces in the vhost probe output so the
    model gets a ready-to-brute-force summary.
    """
    if not html or "<form" not in html.lower():
        return {}
    inputs = _INPUT_NAME_RE.findall(html)
    if not inputs:
        return {}
    action_match = _FORM_ACTION_RE.search(html)
    method_match = _FORM_METHOD_RE.search(html)
    return {
        "action": action_match.group(1) if action_match else "",
        "method": (method_match.group(1) if method_match else "GET").upper(),
        "inputs": inputs,
    }


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
    """Probe well-known paths against the target URL.

    Resolution order for the target URL:
      1. ``ctx['host']`` — populated from ``KRYON_TARGET_HOST`` env by
         ``build_turn_ctx``. This is the authoritative value when the
         engage CLI is running (``engage.py:_run_phase`` sets the env
         right before each phase's pre_hooks).
      2. ``ctx['target']`` — fallback, populated by hostname regex
         scan over the user input. UNRELIABLE because the regex can
         match incidental tokens like ``user.txt`` from a recon
         objective ("find user.txt and root.txt") — Bench Robots
         (2026-05-27) hit this exact false-positive and every probe
         hit http://user.txt/... → all errored.

    Returns a markdown-formatted summary. Empty / missing target
    yields a one-line skip message (not a crash). All transport
    errors are captured per-path; the probe never raises.
    """
    # FASE 11.T.4 — prefer ctx['host'] (env-backed, authoritative) over
    # ctx['target'] (regex-detected, brittle).
    target = (ctx.get("host") or ctx.get("target") or "").strip().rstrip("/")
    if not target:
        return "[web-common-paths] no target in ctx (neither host nor target set)"

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

    lines: list[str] = [f"# 🎯 DETERMINISTIC RECON — Web common paths against {target}"]

    if not interesting:
        lines.append(
            f"\nAll {len(_COMMON_PATHS)} probed paths returned 404 or errored."
            f" The target may be locked down or behind WAF/auth. "
            f"(404: {len(nonexistent)}, errored: {len(errored)})."
        )
        return "\n".join(lines)

    # Extract any /robots.txt disallow entries up-front so the model
    # sees them in the first 3 lines (FASE 11.T.2 — Bench Robots
    # showed qwen3-8b ignoring buried content). Disallow paths are
    # the highest-value finding this probe can produce.
    robots_disallow_paths: list[str] = []
    for path, status, _, body in interesting:
        if path == "/robots.txt" and status == 200 and body:
            for body_line in body.splitlines():
                stripped = body_line.strip()
                if stripped.lower().startswith("disallow:"):
                    value = stripped.split(":", 1)[1].strip()
                    if value:
                        robots_disallow_paths.append(value)
            break

    # FASE 11.U — chain-enumerate sub-paths under each Disallow entry.
    # The bench Robots T.4 result showed the model surfacing disallow
    # paths as findings but never probing them. The model needs LIVE
    # hits (200) at the top of the output to pivot. This step runs a
    # second wave of probes against the disallow paths the FIRST wave
    # discovered.
    live_subpath_hits: list[tuple[str, int, int, str]] = []
    if robots_disallow_paths:
        # Cap to avoid 50+ probes against a target with a long
        # robots.txt. Top N are typically the most relevant on CTFs.
        disallow_targets = robots_disallow_paths[:_MAX_DISALLOW_PATHS_TO_ENUMERATE]
        chain_probes: list[str] = []
        for disallow in disallow_targets:
            base_path = disallow.rstrip("/")
            for sub in _DISALLOW_SUBPATHS:
                full = base_path + sub
                if full and full not in chain_probes:
                    chain_probes.append(full)

        chain_results: list[tuple[str, int, int, str]] = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as ex:
            chain_futures = {
                ex.submit(_probe_path, target, p): p for p in chain_probes
            }
            try:
                for fut in concurrent.futures.as_completed(
                    chain_futures, timeout=_WALL_CLOCK_S
                ):
                    try:
                        chain_results.append(fut.result())
                    except Exception as exc:  # noqa: BLE001
                        path = chain_futures[fut]
                        chain_results.append((path, -1, 0, f"[error] {exc}"))
            except concurrent.futures.TimeoutError:
                logger.debug("disallow-chain wall-clock hit at %ss", _WALL_CLOCK_S)

        # Keep only paths that returned actionable status (200 / 3xx /
        # 401 / 403). 404s under disallow are noise; errors are
        # transport noise.
        live_subpath_hits = [
            r for r in chain_results if r[1] in (200, 301, 302, 307, 308, 401, 403)
        ]

    if robots_disallow_paths:
        lines.append("")
        lines.append("## 🚨 KEY FINDING — /robots.txt exposes Disallow paths")
        lines.append("")
        lines.append(
            "**These paths are intentionally hidden from crawlers but "
            "publicly accessible. They are the FIRST place to investigate "
            "on a recon CTF / web pentest.**"
        )
        lines.append("")
        for path in robots_disallow_paths:
            lines.append(f"- `{target}{path}` ← investigate with curl / gobuster")
        lines.append("")

    # FASE 11.V — detect cross-host redirects (vhost trick) in the
    # chain results. The Robots THM lab redirects /harm/to/self/* to
    # http://robots.thm/... which DNS can't resolve; the only way to
    # see the real content is to probe the IP with Host: robots.thm.
    vhost_findings: list[tuple[str, str, int, str, dict[str, Any]]] = []
    if live_subpath_hits:
        # Detect a single vhost from any redirect Location header.
        detected_vhost = ""
        for _path, status, _size, body in live_subpath_hits:
            if status in (301, 302, 307, 308):
                candidate = _extract_vhost_from_location(body, target)
                if candidate:
                    detected_vhost = candidate
                    break
        if detected_vhost:
            # Re-probe each redirect path with the vhost Host header.
            # Cap at ~6 paths to stay within wall-clock budget.
            redirect_paths = [
                p for p, s, _, _ in live_subpath_hits
                if s in (301, 302, 307, 308)
            ][:6]
            with concurrent.futures.ThreadPoolExecutor(max_workers=4) as ex:
                vhost_futures = {
                    ex.submit(_probe_with_vhost, target, p, detected_vhost): p
                    for p in redirect_paths
                }
                for fut in concurrent.futures.as_completed(
                    vhost_futures, timeout=_WALL_CLOCK_S
                ):
                    p = vhost_futures[fut]
                    try:
                        status, size, body = fut.result()
                    except Exception as exc:  # noqa: BLE001
                        status, size, body = -1, 0, f"[error] {exc}"
                    form = _detect_login_form(body)
                    vhost_findings.append((p, detected_vhost, status, body, form))

    # FASE 11.V — render the vhost block BEFORE the chain enum block
    # because the vhost finding is the highest-leverage signal in the
    # whole output (it's the actual exploitation surface, not just a
    # redirect that needs follow-up).
    if vhost_findings:
        login_forms = [vf for vf in vhost_findings if vf[4]]
        ok_responses = [vf for vf in vhost_findings if vf[2] == 200 and not vf[4]]

        lines.append(f"## 🎯 VHOST DETECTED — `{vhost_findings[0][1]}`")
        lines.append("")
        lines.append(
            f"**The target's redirects point to vhost `{vhost_findings[0][1]}` "
            "(not DNS-resolvable). Probing the target IP with "
            f"`Host: {vhost_findings[0][1]}` header reveals real content.**"
        )
        lines.append("")

        if login_forms:
            # FASE 11.V.2 — frame as FINDING (not as action), so the
            # orchestrator's "convert each line to JSON" instruction
            # picks it up cleanly. Bench V showed the model
            # interpreting "ACCIÓN OBLIGATORIA: emití curl" as "the
            # pre_hook did its job, my job is to execute curl" and
            # then returning [] when its single non-vhost curl
            # didn't find new vulns. Framing as a finding with
            # CWE/severity makes it a natural JSON entry, with the
            # follow-up tools listed as optional remediation_command.
            lines.append("### 🔐 HIDDEN LOGIN FORM — report as HIGH severity finding")
            lines.append("")
            for path, vhost, status, _body, form in login_forms:
                action = form.get("action") or path
                method = form.get("method") or "POST"
                inputs = form.get("inputs", [])
                lines.append(
                    f"- **finding**: `LOGIN_FORM_VHOST_EXPOSED` "
                    f"(CWE-200 + CWE-287, severity HIGH)"
                )
                lines.append(
                    f"  - **host**: `{target}{path}`"
                )
                lines.append(
                    f"  - **vhost**: `{vhost}` (DNS-unresolvable, accessed via Host header)"
                )
                lines.append(
                    f"  - **form**: action=`{action}` method=`{method}` "
                    f"inputs={', '.join(f'`{i}`' for i in inputs)}"
                )
                lines.append(
                    "  - **message**: Login form hidden behind vhost; only "
                    "accessible with `Host: <vhost>` header. Bypasses normal "
                    "discovery."
                )
                lines.append(
                    f"  - **evidence**: `_probe_with_vhost` returned 200 con "
                    f"form fields {inputs} para Host header `{vhost}`."
                )
                lines.append(
                    "  - **remediation_command**: revisar el redirect "
                    "/etc/apache2/sites-enabled/, considerá si el vhost debe "
                    "ser público o restricted."
                )
            lines.append("")
            lines.append(
                "_Optional follow-up tools (NOT required for findings JSON; "
                "useful only si querés escalar)_:"
            )
            for _p, vhost, _s, _b, form in login_forms[:1]:
                action = form.get("action") or login_forms[0][0]
                method = form.get("method") or "POST"
                lines.append(
                    f"- default creds probe: `run_command curl -s -X {method} "
                    f"-H 'Host: {vhost}' -d 'username=admin&password=admin' "
                    f"http://<ip>{action}`"
                )
                lines.append(
                    f"- brute-force: `hydra -L users.txt -P rockyou.txt "
                    f"http-post-form '{action}:username=^USER^&password=^PASS^"
                    f"&login=login:F=incorrect' -H 'Host: {vhost}'`"
                )
                lines.append(
                    f"- sqlmap: `sqlmap --data 'username=admin&password=test' "
                    f"-u http://<ip>{action} --headers='Host: {vhost}' --batch`"
                )
            lines.append("")

        if ok_responses:
            lines.append("### Other 200 responses via vhost")
            for path, _vhost, status, body, _form in ok_responses:
                lines.append(f"- [{status}] `{target}{path}` ({len(body)} bytes)")
                preview = body[:160].replace("\n", " ").replace("\r", "")
                lines.append(f"  preview: {preview!r}")
            lines.append("")

    if live_subpath_hits:
        # FASE 11.U — surface live sub-paths discovered under the
        # disallow entries. These are the actual exploitation
        # surfaces (login forms, admin panels, config files).
        lines.append("## 🔥 DISALLOW PATH ENUMERATION — LIVE sub-paths discovered")
        lines.append("")
        lines.append(
            "**Auto-probed sub-paths under each Disallow entry. The "
            "following returned a non-404 status — these are LIVE "
            "exploitation surfaces. Pivot HERE before re-scanning the "
            "root URL.**"
        )
        lines.append("")
        # Sort: 200 first, then 3xx, then 403, then 401.
        live_subpath_hits.sort(key=_interest_key)
        for path, status, size, _body in live_subpath_hits:
            lines.append(f"- [{status}] `{target}{path}` ({size} bytes)")
        lines.append("")
        lines.append(
            "**ACCIÓN OBLIGATORIA**: para cada path 200 con HTML, emití "
            "`run_command curl -s {target}<path>` para ver el body real. "
            "Si encontrás un login form, intentá credenciales por defecto "
            "(admin/admin, admin/password) Y revisá el body por hints "
            "(comentarios HTML, hidden inputs, JS vars). Si encontrás "
            "config/upload endpoints, probá LFI/RCE."
        )
        lines.append("")
    elif robots_disallow_paths:
        # FASE 11.U — when we tried but nothing came back, tell the
        # model that explicitly so it doesn't try the same probes
        # manually (wasting context).
        lines.append(
            "_Tried 10 sub-paths under each Disallow entry "
            "(/login.php, /admin.php, /index.php, etc.) — none returned 200. "
            "The disallow paths may need brute-force enumeration with "
            "gobuster against a larger wordlist._"
        )
        lines.append("")

    if robots_disallow_paths:
        lines.append(
            "**ACCIÓN OBLIGATORIA**: emití un `run_command curl` "
            "contra CADA Disallow path antes de cerrar este turn. "
            "Si alguno retorna 200 con HTML, enumerá su contenido "
            "con `gobuster dir -u {target}<path> -w common.txt -x php,html,txt`."
        )
        lines.append("")

    lines.append(f"## Interesting paths ({len(interesting)})")
    for path, status, size, body in interesting:
        lines.append(f"- [{status}] {path}  ({size} bytes)")
        if path == "/robots.txt" and body and body.strip():
            # Inline /robots.txt full body — the fact_extractor's
            # _DISALLOW_PATH_RE picks up these literal lines downstream
            # to populate facts.disallow_paths for the planner rules.
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
