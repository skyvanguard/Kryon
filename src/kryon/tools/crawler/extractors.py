"""F108 — Static extractors for the crawler.

Pure-function HTML / JS analyzers. Take a string, return structured
data. No I/O, no side effects. The crawler hooks these onto each
response body it receives.

Extraction layers:

  (A) HTML link surfaces:
      - <a href="...">          → navigational links
      - <link href="...">       → stylesheets, preload, manifest
      - <script src="...">      → external JS (feeds F102 + F107)
      - <img src="...">         → images (useful for SSRF / open-redirect surface)
      - <iframe src="...">      → embedded content
      - <form action="...">     → form endpoints (extracted separately)

  (B) HTML forms:
      Method + action + every <input>/<select>/<textarea> with
      name + type. Surfaces the input parameters that F103/F106
      heuristics consume.

  (C) Meta tags:
      Generator, csrf-token, viewport, etc. — useful for fingerprint
      passes (feeds F104).

  (D) JS endpoint extraction:
      The vast majority of SPA APIs are NOT in the HTML; they are
      string-encoded in the JS bundle. We extract:
        - fetch("/api/...")     / fetch(`https://...`)
        - axios.get("/...")     / axios.post(...)
        - $.ajax({url: "..."})
        - jQuery $.get / $.post
        - URL constants: const API_URL = "..."
        - Absolute paths in strings: "/api/v1/users"
        - Full URLs: "https://api.example.com/foo"
"""

from __future__ import annotations

import html
import re
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlparse, urlunparse

__all__ = [
    "ExtractedLink",
    "ExtractedForm",
    "ExtractedFormField",
    "extract_links_from_html",
    "extract_forms_from_html",
    "extract_endpoints_from_js",
    "extract_script_srcs_from_html",
    "extract_meta_tags_from_html",
    "urljoin_safe",
]


# ----- HTML link extractors -------------------------------------------------

# <tag ... attr="value" ...> capture. Tolerates single/double quotes
# and unquoted values. The leading anchor (?<= or boundary) avoids
# matching inside other attribute names.
def _href_pattern(tag: str, attr: str) -> re.Pattern:
    # Match <tag ... attr="value" or attr='value' or attr=value
    return re.compile(
        rf"<{tag}\b[^>]*?\b{attr}\s*=\s*(?:\"([^\"]*)\"|'([^']*)'|([^\s>]+))",
        re.IGNORECASE | re.DOTALL,
    )


_A_HREF_RE = _href_pattern("a", "href")
_LINK_HREF_RE = _href_pattern("link", "href")
_SCRIPT_SRC_RE = _href_pattern("script", "src")
_IMG_SRC_RE = _href_pattern("img", "src")
_IFRAME_SRC_RE = _href_pattern("iframe", "src")
_FORM_OPEN_RE = re.compile(r"<form\b[^>]*>", re.IGNORECASE)
_FORM_BLOCK_RE = re.compile(
    r"<form\b([^>]*)>(.*?)</form>", re.IGNORECASE | re.DOTALL
)
_INPUT_RE = re.compile(
    r"<(?:input|textarea|select)\b([^>]*)/?>",
    re.IGNORECASE | re.DOTALL,
)
_ATTR_RE = re.compile(
    r"""\b([a-zA-Z_-][\w-]*)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))""",
    re.DOTALL,
)
# Boolean attributes appear without `=value`: e.g. `<input required>`.
_BOOL_ATTR_RE = re.compile(
    r"""\b(required|disabled|readonly|checked|selected|multiple|autofocus|hidden|novalidate|formnovalidate|autoplay|controls|loop|muted|defer|async)\b(?!\s*=)""",
    re.IGNORECASE,
)
_META_RE = re.compile(r"<meta\b([^>]*)/?>", re.IGNORECASE)


@dataclass(frozen=True)
class ExtractedLink:
    url: str
    source_tag: str  # "a" / "link" / "script" / "img" / "iframe"
    rel: str = ""  # for <link rel=...>


@dataclass(frozen=True)
class ExtractedFormField:
    name: str
    field_type: str  # "text" / "password" / "email" / "hidden" / "select" / etc.
    value: str = ""
    required: bool = False


@dataclass(frozen=True)
class ExtractedForm:
    action: str  # absolute URL of form action (or "" if same-origin form)
    method: str  # "GET" / "POST"
    fields: tuple[ExtractedFormField, ...] = field(default_factory=tuple)


def _first_group(m: re.Match) -> str:
    """Helper: return whichever group matched (double-quote, single-quote,
    or unquoted variant)."""
    for g in m.groups():
        if g is not None:
            return g
    return ""


def _parse_attrs(raw: str) -> dict[str, str]:
    """Parse `attr=value` pairs from an HTML tag's attribute string."""
    out: dict[str, str] = {}
    for m in _ATTR_RE.finditer(raw):
        key = m.group(1).lower()
        # whichever quote variant matched
        val = m.group(2) if m.group(2) is not None else (
            m.group(3) if m.group(3) is not None else m.group(4) or ""
        )
        out[key] = html.unescape(val)
    # Boolean attributes (no `=value`)
    for m in _BOOL_ATTR_RE.finditer(raw):
        out.setdefault(m.group(1).lower(), "")
    return out


def urljoin_safe(base_url: str, ref: str) -> str:
    """urljoin + scheme allowlist. Returns "" for non-HTTP(S) schemes
    (javascript:, data:, mailto:, etc.) or malformed refs."""
    if not ref:
        return ""
    ref = ref.strip()
    if not ref:
        return ""
    # Block dangerous schemes immediately
    low = ref.lower()
    for scheme in ("javascript:", "data:", "mailto:", "tel:", "file:", "vbscript:"):
        if low.startswith(scheme):
            return ""
    # Fragment-only refs are not navigational
    if ref.startswith("#"):
        return ""
    try:
        joined = urljoin(base_url, ref)
    except Exception:
        return ""
    parsed = urlparse(joined)
    if parsed.scheme.lower() not in ("http", "https"):
        return ""
    # Strip the fragment — it doesn't change the resource
    if parsed.fragment:
        joined = urlunparse(parsed._replace(fragment=""))
    return joined


def _extract_with_pattern(
    pattern: re.Pattern, body: str, base_url: str, source_tag: str
) -> list[ExtractedLink]:
    out: list[ExtractedLink] = []
    seen: set[str] = set()
    for m in pattern.finditer(body):
        raw = _first_group(m)
        if not raw:
            continue
        joined = urljoin_safe(base_url, html.unescape(raw))
        if not joined or joined in seen:
            continue
        seen.add(joined)
        out.append(ExtractedLink(url=joined, source_tag=source_tag))
    return out


def extract_links_from_html(body: str, base_url: str) -> list[ExtractedLink]:
    """Extract all link-bearing tags. Dedupes within this call."""
    if not body:
        return []
    out: list[ExtractedLink] = []
    out.extend(_extract_with_pattern(_A_HREF_RE, body, base_url, "a"))
    out.extend(_extract_with_pattern(_LINK_HREF_RE, body, base_url, "link"))
    out.extend(_extract_with_pattern(_SCRIPT_SRC_RE, body, base_url, "script"))
    out.extend(_extract_with_pattern(_IMG_SRC_RE, body, base_url, "img"))
    out.extend(_extract_with_pattern(_IFRAME_SRC_RE, body, base_url, "iframe"))
    return out


def extract_script_srcs_from_html(body: str, base_url: str) -> list[str]:
    """Return just the external JS script URLs (feeds F102 directly)."""
    return [
        link.url
        for link in _extract_with_pattern(_SCRIPT_SRC_RE, body, base_url, "script")
    ]


def extract_meta_tags_from_html(body: str) -> dict[str, str]:
    """Extract `<meta name=... content=...>` pairs (feeds F104)."""
    out: dict[str, str] = {}
    if not body:
        return out
    for m in _META_RE.finditer(body):
        attrs = _parse_attrs(m.group(1))
        key = attrs.get("name") or attrs.get("property") or attrs.get("http-equiv")
        content = attrs.get("content")
        if key and content is not None:
            out[key.lower()] = content
    return out


def extract_forms_from_html(body: str, base_url: str) -> list[ExtractedForm]:
    """Extract every <form>, including its <input>/<select>/<textarea>
    fields. Returns ExtractedForm objects with absolute action URLs."""
    if not body:
        return []
    forms: list[ExtractedForm] = []
    for m in _FORM_BLOCK_RE.finditer(body):
        form_attrs = _parse_attrs(m.group(1))
        inner = m.group(2)
        action_raw = form_attrs.get("action", "")
        action_url = (
            urljoin_safe(base_url, action_raw)
            if action_raw
            else base_url
        )
        method = (form_attrs.get("method") or "GET").upper()
        if method not in ("GET", "POST"):
            method = "GET"

        fields: list[ExtractedFormField] = []
        seen: set[str] = set()
        for fm in _INPUT_RE.finditer(inner):
            iattrs = _parse_attrs(fm.group(1))
            fname = iattrs.get("name", "")
            if not fname or fname in seen:
                continue
            seen.add(fname)
            ftype = iattrs.get("type", "text").lower()
            fvalue = iattrs.get("value", "")
            required = "required" in iattrs or iattrs.get("required") == ""
            fields.append(
                ExtractedFormField(
                    name=fname,
                    field_type=ftype,
                    value=fvalue,
                    required=required,
                )
            )
        forms.append(
            ExtractedForm(action=action_url, method=method, fields=tuple(fields))
        )
    return forms


# ----- JavaScript endpoint extraction ---------------------------------------

# Quoted string that looks like a URL or absolute path.
# IMPORTANT: this pattern is intentionally simple (character class,
# no backreference, no lookahead) to avoid catastrophic backtracking
# (ReDoS) on minified JS bundles. We pay for that by NOT handling
# escaped quotes inside the string — but URLs almost never contain
# escaped quotes, so the tradeoff is right.
_JS_DOUBLE_QUOTE_RE = re.compile(r'"([^"\\\n\r]{1,500})"')
_JS_SINGLE_QUOTE_RE = re.compile(r"'([^'\\\n\r]{1,500})'")
_JS_BACKTICK_RE = re.compile(r"`([^`$\n\r]{1,500})`")

# fetch / axios / $.ajax / $.get / $.post — capture the URL argument
_FETCH_CALL_RE = re.compile(
    r"""\bfetch\s*\(\s*(['"`])([^'"`]+)\1""", re.DOTALL
)
_AXIOS_CALL_RE = re.compile(
    r"""\baxios(?:\.(?:get|post|put|delete|patch|head|request))?\s*\(\s*(['"`])([^'"`]+)\1""",
    re.DOTALL | re.IGNORECASE,
)
_JQ_AJAX_URL_RE = re.compile(
    r"""\$\.(?:ajax|get|post|getJSON)\s*\(\s*(?:\{[^}]*?url\s*:\s*)?(['"])([^'"]+)\1""",
    re.DOTALL,
)
_XHR_OPEN_RE = re.compile(
    r"""\.open\s*\(\s*(['"])(GET|POST|PUT|DELETE|PATCH|HEAD)\1\s*,\s*(['"])([^'"]+)\3""",
    re.DOTALL | re.IGNORECASE,
)

# Looks-like-URL filter: full URLs or absolute paths (/api/, /v1/, etc.)
# AND must contain at least one of these "API-ish" markers.
_URL_LOOKS_LIKE_API_RE = re.compile(
    r"""^(?:https?://[^\s'"<>]+|/(?:api|v\d+|graphql|rest|services|ajax|admin|auth|login|logout|users?|account|session)[^?#'"]*)""",
    re.IGNORECASE,
)
# Generic "absolute path that's not just a slash"
_ABSOLUTE_PATH_RE = re.compile(r"^/[\w/.-]+(?:\?[\w&=.%-]*)?$")
# Full URL with scheme
_FULL_URL_RE = re.compile(r"^https?://[^\s'\"<>]+$")


def _classify_js_url_candidate(value: str) -> bool:
    """Heuristic: is this string a plausible endpoint?"""
    if not value or len(value) < 2 or len(value) > 500:
        return False
    # Reject strings that contain spaces, newlines, or angle brackets
    if any(c in value for c in (" ", "\n", "\r", "\t", "<", ">")):
        return False
    # Reject strings that look like CSS color codes / hex / short ids
    if re.match(r"^#[0-9a-f]+$", value, re.IGNORECASE):
        return False
    # Strong matches
    if _FULL_URL_RE.match(value):
        return True
    if _URL_LOOKS_LIKE_API_RE.match(value):
        return True
    return False


def extract_endpoints_from_js(
    js_body: str, base_url: str
) -> list[str]:
    """Extract candidate endpoint URLs from a JavaScript bundle.

    Returns absolute URLs, deduped. Combines explicit call-site
    detection (fetch/axios/$.ajax/XHR.open) and a fallback scan for
    quoted strings that look like API endpoints.
    """
    if not js_body:
        return []
    found: set[str] = set()
    out: list[str] = []

    def _add(raw: str) -> None:
        joined = urljoin_safe(base_url, raw)
        if joined and joined not in found:
            found.add(joined)
            out.append(joined)

    # Explicit call-site patterns — high confidence
    for m in _FETCH_CALL_RE.finditer(js_body):
        _add(m.group(2))
    for m in _AXIOS_CALL_RE.finditer(js_body):
        _add(m.group(2))
    for m in _JQ_AJAX_URL_RE.finditer(js_body):
        _add(m.group(2))
    for m in _XHR_OPEN_RE.finditer(js_body):
        _add(m.group(4))

    # Fallback: any quoted string that looks like an endpoint.
    # Use separate single/double-quote regexes (no backreference) to
    # keep this O(n) and ReDoS-safe.
    for pattern in (_JS_DOUBLE_QUOTE_RE, _JS_SINGLE_QUOTE_RE, _JS_BACKTICK_RE):
        for m in pattern.finditer(js_body):
            value = m.group(1)
            if not _classify_js_url_candidate(value):
                continue
            _add(value)

    return out
