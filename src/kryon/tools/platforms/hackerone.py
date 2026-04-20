"""HackerOne platform integration (F65).

Provides four agent-facing tools + a scope-enforcement helper used by
:func:`kryon.tools.appsec.web_pentest_tool.run_web_pentest`:

    h1_list_programs()             — programs the authenticated user participates in
    h1_get_program_scope(handle)   — in-scope assets for a program
    h1_list_my_reports(state)      — existing submissions
    h1_submit_report(...)          — create a new submission (gated by request_approval)
    is_in_scope(url, handle)       — Python helper, NOT a tool — for the
                                     run_web_pentest guardrail

Two API flavors on HackerOne — auth is the same HTTP Basic, but the
endpoint tree differs:

  - **Hacker accounts** (individual researchers, default for most
    users) use ``/v1/hackers/*``. The Basic Auth username is the
    HackerOne profile username (what appears after hackerone.com/),
    and the API token is generated via /settings/api. There is NO
    custom per-token identifier — the UI shows only the secret.
  - **Organization tokens** use ``/v1/me/*`` and ``/v1/organizations/*``.
    Org tokens DO have a custom identifier field filled at creation.

This module detects automatically: try hacker endpoints first, fall
back to ``/v1/me/*`` on 404/403. Env vars:

    HACKERONE_API_USERNAME  — profile username (hacker) OR custom
                              identifier (org token)
    HACKERONE_API_TOKEN     — API token

Both read from environment at each tool invocation. **Never hardcode
the token** — the codebase is open-source and is commonly forked.

Rate limit:
    HackerOne allows 600 requests / minute per token. We keep a simple
    in-process counter; if the tool hits the limit it returns a soft
    error rather than raising — the LLM can then back off.

Security notes:
- Out-of-scope probing is a HackerOne ToS violation and will get you
  banned (possibly prosecuted in some jurisdictions). run_web_pentest
  supports ``hackerone_program_handle`` which forces scope validation
  BEFORE any probe runs.
- Submission (:func:`h1_submit_report`) requires an explicit
  ``request_approval`` step in production flows.
"""

from __future__ import annotations

import base64
import fnmatch
import json
import os
import re
import threading
import time
from typing import Any, Optional
from urllib.parse import urlparse

try:
    import requests
except ImportError:  # pragma: no cover
    requests = None  # type: ignore

from kryon.sdk.agents import function_tool

_H1_BASE = os.environ.get("HACKERONE_API_BASE", "https://api.hackerone.com/v1")

# Soft per-process rate limiter: 600 req/min per HackerOne's published limit.
_RL_LOCK = threading.Lock()
_RL_CALLS: list[float] = []
_RL_MAX_PER_MINUTE = 600


def _auth() -> Optional[tuple[str, str]]:
    """Return (username, token) tuple or None if env vars missing."""
    user = os.environ.get("HACKERONE_API_USERNAME", "").strip()
    token = os.environ.get("HACKERONE_API_TOKEN", "").strip()
    if not user or not token:
        return None
    return (user, token)


def _auth_error() -> dict[str, str]:
    return {
        "error": (
            "HackerOne credentials not configured. Set HACKERONE_API_USERNAME "
            "and HACKERONE_API_TOKEN environment variables. Generate the "
            "token at https://hackerone.com/settings/api."
        ),
        "hint": "cp .env.example ~/.kryon/secrets.env; chmod 600 ~/.kryon/secrets.env",
    }


def _rate_limit_ok() -> bool:
    """Return True iff we're under 600 req/min. Best-effort; not SMP-safe
    beyond the single process."""
    now = time.time()
    with _RL_LOCK:
        cutoff = now - 60.0
        while _RL_CALLS and _RL_CALLS[0] < cutoff:
            _RL_CALLS.pop(0)
        if len(_RL_CALLS) >= _RL_MAX_PER_MINUTE:
            return False
        _RL_CALLS.append(now)
    return True


def _get(path: str, params: Optional[dict] = None) -> dict[str, Any]:
    """Authenticated GET against HackerOne API. Returns dict (or an
    ``{"error": "..."}`` shape on failure)."""
    if requests is None:
        return {"error": "requests library not available"}
    creds = _auth()
    if creds is None:
        return _auth_error()
    if not _rate_limit_ok():
        return {"error": "HackerOne rate limit (600 req/min) reached; retry shortly"}

    url = path if path.startswith("http") else f"{_H1_BASE}{path}"
    try:
        resp = requests.get(
            url,
            auth=creds,
            params=params or {},
            timeout=20,
            headers={"Accept": "application/json"},
        )
    except requests.RequestException as exc:
        return {"error": f"{type(exc).__name__}: {exc}"}

    if resp.status_code == 401:
        return {"error": "HackerOne auth rejected — check HACKERONE_API_USERNAME / _TOKEN"}
    if resp.status_code == 403:
        return {"error": "HackerOne 403 — token lacks scope for this endpoint"}
    if resp.status_code == 404:
        return {"error": f"HackerOne 404 for {url}"}
    if resp.status_code >= 500:
        return {"error": f"HackerOne server error {resp.status_code}"}

    try:
        return resp.json()
    except json.JSONDecodeError:
        return {"error": f"non-JSON response from HackerOne (status {resp.status_code})"}


def _post(path: str, payload: dict) -> dict[str, Any]:
    if requests is None:
        return {"error": "requests library not available"}
    creds = _auth()
    if creds is None:
        return _auth_error()
    if not _rate_limit_ok():
        return {"error": "HackerOne rate limit reached"}

    url = f"{_H1_BASE}{path}"
    try:
        resp = requests.post(
            url, auth=creds, json=payload, timeout=30,
            headers={"Accept": "application/json", "Content-Type": "application/json"},
        )
    except requests.RequestException as exc:
        return {"error": f"{type(exc).__name__}: {exc}"}

    if resp.status_code >= 400:
        try:
            body = resp.json()
        except Exception:  # noqa: BLE001
            body = {"raw": resp.text[:500]}
        return {"error": f"HackerOne {resp.status_code}", "response": body}

    try:
        return resp.json()
    except json.JSONDecodeError:
        return {"error": "non-JSON response"}


# ---------------------------------------------------------------------------
# Scope matcher — used by is_in_scope() and the run_web_pentest guard
# ---------------------------------------------------------------------------


def _parse_target(url: str) -> tuple[str, str, str]:
    """(scheme, host, path_or_full_url) for use in matchers."""
    parsed = urlparse(url)
    return parsed.scheme, parsed.netloc, url


def _match_asset(target_url: str, asset_id: str, asset_type: str) -> bool:
    """True iff ``target_url`` is covered by an H1 scope asset.

    Supported asset_type values we handle: "URL", "WILDCARD", "DOMAIN"
    and any value containing "URL". Non-URL assets (android/ios apps,
    source code repos) always fall through to False here — those need
    dedicated matchers.
    """
    if not asset_id or not target_url:
        return False

    scheme, host, full = _parse_target(target_url)
    if not host:
        return False

    t = (asset_type or "").upper()
    needle = asset_id.strip()

    # Handle wildcard form "*.example.com"
    if needle.startswith("*."):
        root = needle[2:]
        return host == root or host.endswith("." + root)

    # Bare domain form (no scheme)
    if "://" not in needle:
        # Treat as a domain match; accept host == needle or host endswith .needle
        if host == needle:
            return True
        if host.endswith("." + needle):
            return True
        # Also accept explicit path prefix like "api.example.com/v1"
        if "/" in needle:
            dom, path_prefix = needle.split("/", 1)
            if (host == dom or host.endswith("." + dom)) and urlparse(target_url).path.startswith("/" + path_prefix):
                return True
        return False

    # Full URL form — match by host + path prefix
    a = urlparse(needle)
    if a.netloc != host:
        # Wildcard subdomains in the URL host
        if a.netloc.startswith("*."):
            root = a.netloc[2:]
            if host != root and not host.endswith("." + root):
                return False
        else:
            return False
    # Path prefix
    target_path = urlparse(target_url).path or "/"
    asset_path = a.path or "/"
    return target_path.startswith(asset_path)


def is_in_scope(
    target_url: str, program_handle: str, scope_cache: Optional[dict] = None,
) -> tuple[bool, str]:
    """Python helper (NOT a @function_tool).

    Fetches structured_scopes for ``program_handle`` (or uses the
    pre-fetched cache dict) and returns ``(in_scope, reason)`` where
    reason explains the matching asset id or why the check failed.

    Returned ``in_scope`` is conservative: if the API call fails OR no
    asset matches, ``False`` is returned. Callers treat False as BLOCK.
    """
    if scope_cache is None:
        scope_cache = _get(f"/hackers/programs/{program_handle}/structured_scopes")
        if "error" in scope_cache and "401" in str(scope_cache.get("error", "")):
            scope_cache = _get(f"/programs/{program_handle}/structured_scopes")
    if "error" in scope_cache:
        return False, f"scope lookup failed: {scope_cache['error']}"

    # Deny-over-allow policy: any matching asset with eligible_for_
    # submission=False is an explicit exclusion that vetoes a broader
    # wildcard. Programs commonly scope "*.example.com" + exclude
    # specific subdomains (admin.example.com, internal.*, etc).
    assets = scope_cache.get("data") or []
    matched_allow: Optional[str] = None
    matched_allow_type: str = ""
    for asset in assets:
        attrs = asset.get("attributes") or {}
        asset_id = attrs.get("asset_identifier") or ""
        asset_type = attrs.get("asset_type") or ""
        if not _match_asset(target_url, asset_id, asset_type):
            continue
        if not attrs.get("eligible_for_submission"):
            return (
                False,
                f"explicit out-of-scope: asset {asset_id!r} is marked "
                f"not-eligible-for-submission in {program_handle}",
            )
        if matched_allow is None:
            matched_allow = asset_id
            matched_allow_type = asset_type

    if matched_allow is not None:
        return True, f"matches asset {matched_allow!r} (type={matched_allow_type})"

    return False, f"no asset in {program_handle} matches {target_url}"


# ---------------------------------------------------------------------------
# @function_tool wrappers
# ---------------------------------------------------------------------------


@function_tool(strict_mode=False)
def h1_list_programs(limit: int = 25) -> str:
    """List HackerOne programs you participate in as a researcher.

    Args:
        limit: Max programs to return (server-side capped at 100 per page).

    Returns:
        JSON string with ``programs`` array, each with handle, name,
        submission_state, offers_bounties, offers_swag, policy_url.
    """
    # Try hacker endpoint first (default for individual accounts); fall
    # back to /me/programs for organization tokens.
    data = _get("/hackers/programs", params={"page[size]": min(max(limit, 1), 100)})
    if "error" in data and "401" not in str(data.get("error", "")):
        data = _get("/me/programs", params={"page[size]": min(max(limit, 1), 100)})
    if "error" in data:
        return json.dumps(data)

    programs = []
    for item in (data.get("data") or [])[:limit]:
        attrs = item.get("attributes") or {}
        programs.append({
            "handle": attrs.get("handle"),
            "name": attrs.get("name"),
            "submission_state": attrs.get("submission_state"),
            "offers_bounties": attrs.get("offers_bounties"),
            "offers_swag": attrs.get("offers_swag"),
            "policy_url": f"https://hackerone.com/{attrs.get('handle', '')}",
        })
    return json.dumps({"count": len(programs), "programs": programs})


@function_tool(strict_mode=False)
def h1_get_program_scope(program_handle: str) -> str:
    """Return in-scope assets for a HackerOne program.

    Call this BEFORE running any probes. Pass the resulting data to
    ``run_web_pentest(hackerone_program_handle=...)`` so the scope
    guard fires before any request hits the target.

    Args:
        program_handle: The program's HackerOne handle (e.g. 'security').

    Returns:
        JSON string with eligible assets (asset_identifier, asset_type,
        eligible_for_bounty, eligible_for_submission, instruction).
    """
    # Hacker-first, fall back to org-scoped endpoint on 401 (org tokens
    # use /programs/<h>/... instead of /hackers/programs/<h>/...).
    data = _get(f"/hackers/programs/{program_handle}/structured_scopes")
    if "error" in data and "401" in str(data.get("error", "")):
        data = _get(f"/programs/{program_handle}/structured_scopes")
    if "error" in data:
        return json.dumps(data)

    assets = []
    for item in data.get("data") or []:
        attrs = item.get("attributes") or {}
        assets.append({
            "asset_identifier": attrs.get("asset_identifier"),
            "asset_type": attrs.get("asset_type"),
            "eligible_for_bounty": attrs.get("eligible_for_bounty"),
            "eligible_for_submission": attrs.get("eligible_for_submission"),
            "instruction": (attrs.get("instruction") or "")[:512],
            "max_severity": attrs.get("max_severity"),
        })
    eligible = [a for a in assets if a.get("eligible_for_submission")]
    return json.dumps({
        "program": program_handle,
        "total_assets": len(assets),
        "eligible_assets": len(eligible),
        "assets": assets,
    })


@function_tool(strict_mode=False)
def h1_list_my_reports(state: str = "new", limit: int = 20) -> str:
    """List your HackerOne submissions.

    Args:
        state: One of new, triaged, resolved, informative, duplicate,
            not-applicable, spam. Defaults to 'new' (recently submitted).
        limit: Max reports to return.

    Returns:
        JSON with report id, title, state, severity, created_at,
        program_handle per report.
    """
    # Hacker endpoint first, then fall back to org endpoint.
    params = {"filter[state][]": state, "page[size]": min(max(limit, 1), 100)}
    data = _get("/hackers/reports", params=params)
    if "error" in data and "401" not in str(data.get("error", "")):
        data = _get("/me/reports", params=params)
    if "error" in data:
        return json.dumps(data)

    reports = []
    for item in (data.get("data") or [])[:limit]:
        attrs = item.get("attributes") or {}
        program = (item.get("relationships") or {}).get("program") or {}
        program_data = (program.get("data") or {}).get("attributes") or {}
        reports.append({
            "id": item.get("id"),
            "title": attrs.get("title"),
            "state": attrs.get("state"),
            "severity": attrs.get("severity_rating"),
            "created_at": attrs.get("created_at"),
            "vulnerability_types": attrs.get("vulnerability_information") or "",
            "program_handle": program_data.get("handle") or "",
        })
    return json.dumps({"count": len(reports), "state": state, "reports": reports})


@function_tool(strict_mode=False)
def h1_submit_report(
    program_handle: str,
    title: str,
    severity: str,
    vulnerability_info: str,
    impact: str,
    steps_to_reproduce: str,
    weakness_id: int = 0,
) -> str:
    """Submit a new report to a HackerOne program.

    **Do NOT call this without explicit operator approval** — this is
    a state-changing operation visible to the program team. The LLM
    should pair this with ``request_approval`` so the operator signs
    off on the exact text before submission.

    Args:
        program_handle: Target program handle.
        title: Concise vulnerability title.
        severity: one of 'none', 'low', 'medium', 'high', 'critical'.
        vulnerability_info: Full finding description. Include POC URL,
            request/response pair, impact narrative.
        impact: Business-impact paragraph (what an attacker gains).
        steps_to_reproduce: Numbered reproduction steps. Must be
            copy-paste reproducible.
        weakness_id: Optional HackerOne weakness id (CWE mapping from
            F59 cwe_mapping can be converted here).

    Returns:
        JSON with created report id + url on success, or error details.
    """
    if severity.lower() not in {"none", "low", "medium", "high", "critical"}:
        return json.dumps({"error": f"invalid severity {severity!r}"})

    # Resolve program to its relationship id (hacker-first, org fallback)
    progs = _get("/hackers/programs", params={"page[size]": 100})
    if "error" in progs and "401" not in str(progs.get("error", "")):
        progs = _get("/me/programs", params={"page[size]": 100})
    if "error" in progs:
        return json.dumps(progs)
    program_id: Optional[str] = None
    for item in progs.get("data") or []:
        attrs = item.get("attributes") or {}
        if attrs.get("handle") == program_handle:
            program_id = item.get("id")
            break
    if not program_id:
        return json.dumps({"error": f"program {program_handle!r} not found or you don't participate"})

    # Build full report body; include a structured vulnerability section.
    body = (
        f"## Summary\n{vulnerability_info}\n\n"
        f"## Impact\n{impact}\n\n"
        f"## Steps to reproduce\n{steps_to_reproduce}\n\n"
        "---\n"
        "Submitted via Kryon F65 integration."
    )

    payload = {
        "data": {
            "type": "report",
            "attributes": {
                "team_handle": program_handle,
                "title": title,
                "vulnerability_information": body,
                "severity_rating": severity.lower(),
            },
            "relationships": {
                "weakness": (
                    {"data": {"type": "weakness", "id": str(weakness_id)}}
                    if weakness_id else None
                ),
            },
        },
    }
    # Prune None relationships
    rels = payload["data"]["relationships"]
    payload["data"]["relationships"] = {k: v for k, v in rels.items() if v is not None}

    data = _post("/reports", payload)
    if "error" in data:
        return json.dumps(data)

    created = data.get("data") or {}
    rid = created.get("id")
    return json.dumps({
        "submitted": True,
        "report_id": rid,
        "url": f"https://hackerone.com/reports/{rid}" if rid else None,
        "title": title,
        "severity": severity,
    })


@function_tool(strict_mode=False)
def h1_assert_in_scope(target_url: str, program_handle: str) -> str:
    """Validate that ``target_url`` is in-scope for a HackerOne program.

    Call this BEFORE any probe to enforce the program's ToS. Returns
    JSON with ``{"in_scope": bool, "reason": "..."}``. The LLM should
    refuse to probe when in_scope=false.
    """
    ok, reason = is_in_scope(target_url, program_handle)
    return json.dumps({
        "target_url": target_url,
        "program": program_handle,
        "in_scope": ok,
        "reason": reason,
    })
