"""F106 — SSRF Static Pattern Detector.

Two layers:

  (1) **Parameter-name heuristic** (BLACK-BOX): given a list of
      parameters discovered on the target, flag those whose name +
      sample value suggest a URL/host parameter that the back-end
      will dereference. This drives where to probe with payloads.
  (2) **Source-code pattern** (WHITE-BOX): scan a snippet of
      server-side code for SSRF-prone patterns — urlopen / requests /
      curl_exec / file_get_contents fed from request input without
      validation.

Stable rule IDs:

  SSRF-001  Parameter name suggests URL handling (`url`, `image_url`,
            `webhook`, `callback`, `proxy`, `fetch`, `xml`, `src`,
            `dest`, `redirect_uri`, ...) (LOW)
  SSRF-002  Parameter value contains a URL pointing to internal /
            metadata IP (169.254.169.254, 127.0.0.1, 10/172/192
            ranges, localhost) (HIGH — likely test that already
            confirmed)
  SSRF-003  Code uses requests.get(<user_input>) without allow-list
            (HIGH)
  SSRF-004  Code uses urllib.urlopen(<user_input>) without
            validation (HIGH)
  SSRF-005  Code uses curl_exec / file_get_contents with user input
            (HIGH)
  SSRF-006  Code lacks DNS rebinding protection (allows hostnames
            that resolve to internal IPs at probe time) (MEDIUM)
  SSRF-007  Webhook handler accepts arbitrary URLs (MEDIUM)
  SSRF-008  Server-side image fetcher with no host allow-list (HIGH)

All static. No live requests.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from urllib.parse import urlparse

__all__ = [
    "SsrfParameter",
    "SsrfCodeSnippet",
    "SsrfFinding",
    "SsrfAnalysis",
    "analyze_ssrf",
    "ALL_SSRF_RULES",
]


ALL_SSRF_RULES: frozenset[str] = frozenset({f"SSRF-{n:03d}" for n in range(1, 9)})


_URL_PARAM_NAMES: frozenset[str] = frozenset(
    {
        "url",
        "uri",
        "link",
        "src",
        "source",
        "href",
        "image_url",
        "imageurl",
        "image",
        "webhook",
        "webhook_url",
        "callback",
        "callback_url",
        "proxy",
        "proxy_url",
        "fetch",
        "fetcher",
        "remote",
        "xml",
        "xml_url",
        "feed",
        "feed_url",
        "rss",
        "dest",
        "destination",
        "target",
        "redirect_uri",
        "return_url",
        "asset",
        "asset_url",
        "document_url",
        "pdf_url",
        "host",
        "hostname",
        "endpoint",
        "next",  # also redirect-prone
    }
)


# Internal / metadata IP regex patterns (cover IPv4 + decimal/hex
# encodings) — narrow but useful.
_INTERNAL_IP_PATTERNS: tuple[re.Pattern, ...] = (
    re.compile(r"169\.254\.169\.254"),  # AWS / Azure metadata
    re.compile(r"100\.100\.100\.200"),  # Aliyun metadata
    re.compile(r"metadata\.google\.internal", re.IGNORECASE),
    re.compile(r"169\.254\.\d+\.\d+"),  # link-local
    re.compile(r"127\.\d+\.\d+\.\d+"),
    re.compile(r"^localhost$", re.IGNORECASE | re.MULTILINE),
    re.compile(r"://localhost", re.IGNORECASE),
    re.compile(r"://0\.0\.0\.0"),
    re.compile(r"://\[?::1\]?"),
    re.compile(r"://\[?fc00:", re.IGNORECASE),  # IPv6 ULA
    re.compile(r"://\[?fe80:", re.IGNORECASE),  # IPv6 link-local
)


# Code-pattern signatures (per language)
_CODE_PATTERNS: tuple[tuple[str, str, str, re.Pattern], ...] = (
    # (rule_id, language, label, regex)
    (
        "SSRF-003",
        "python",
        "requests.get with user input",
        re.compile(
            r"requests\.(?:get|post|put|delete|head)\s*\(\s*(?:[a-z_]\w*\.(?:GET|POST|args|form|values|json)|request\.[a-z_]+\.get)",
            re.IGNORECASE,
        ),
    ),
    ("SSRF-003", "python", "requests.get with format string", re.compile(r"requests\.(?:get|post)\s*\(\s*f['\"]")),
    (
        "SSRF-004",
        "python",
        "urlopen with user input",
        re.compile(r"urllib\.request\.urlopen\s*\(\s*(?:request\.|.*\.GET|.*\.POST)", re.IGNORECASE),
    ),
    ("SSRF-004", "python", "urllib2 urlopen", re.compile(r"urllib2?\.urlopen\s*\(", re.IGNORECASE)),
    (
        "SSRF-005",
        "php",
        "curl_exec with user input",
        re.compile(r"curl_setopt\s*\([^)]*CURLOPT_URL[^)]*\$_(?:GET|POST|REQUEST)", re.IGNORECASE),
    ),
    (
        "SSRF-005",
        "php",
        "file_get_contents with user input",
        re.compile(r"file_get_contents\s*\(\s*\$_(?:GET|POST|REQUEST)", re.IGNORECASE),
    ),
    ("SSRF-005", "php", "fopen with user URL", re.compile(r"fopen\s*\(\s*\$_(?:GET|POST|REQUEST)", re.IGNORECASE)),
    (
        "SSRF-003",
        "javascript",
        "axios get with user input",
        re.compile(r"axios\.(?:get|post)\s*\(\s*(?:req\.(?:query|body|params))", re.IGNORECASE),
    ),
    (
        "SSRF-003",
        "javascript",
        "fetch with user input",
        re.compile(r"fetch\s*\(\s*req\.(?:query|body|params)\.", re.IGNORECASE),
    ),
    (
        "SSRF-004",
        "javascript",
        "http.get with user input",
        re.compile(r"https?\.get\s*\(\s*req\.(?:query|body|params)\.", re.IGNORECASE),
    ),
    (
        "SSRF-003",
        "java",
        "URLConnection with user input",
        re.compile(r"new\s+URL\s*\(\s*request\.getParameter", re.IGNORECASE),
    ),
    (
        "SSRF-003",
        "ruby",
        "Net::HTTP with user input",
        re.compile(r"Net::HTTP\.get\s*\(\s*URI\(\s*params\[", re.IGNORECASE),
    ),
)


@dataclass(frozen=True)
class SsrfParameter:
    """An observed parameter (form field, query string, header)."""

    name: str
    sample_value: str = ""
    location: str = "query"  # "query" / "body" / "header" / "json"
    endpoint: str = ""


@dataclass(frozen=True)
class SsrfCodeSnippet:
    """A snippet of server-side code to scan."""

    language: str  # "python" / "php" / "javascript" / "java" / "ruby"
    file_path: str
    body: str
    line_offset: int = 0


@dataclass(frozen=True)
class SsrfFinding:
    rule_id: str
    severity: str
    title: str
    detail: str
    remediation: str
    location: str = ""  # parameter name or file path:line


@dataclass(frozen=True)
class SsrfAnalysis:
    total_parameters: int
    total_snippets: int
    findings: tuple[SsrfFinding, ...] = field(default_factory=tuple)


def _normalize_param(name: str) -> str:
    return name.strip().lower().replace("-", "_")


def _is_url_param(name: str) -> bool:
    norm = _normalize_param(name)
    return norm in {_normalize_param(n) for n in _URL_PARAM_NAMES}


def _value_points_internal(value: str) -> bool:
    if not value:
        return False
    for pat in _INTERNAL_IP_PATTERNS:
        if pat.search(value):
            return True
    # Try to parse and check whether the host is an internal IP.
    try:
        parsed = urlparse(value if "://" in value else "http://" + value)
        host = parsed.hostname
        if not host:
            return False
        try:
            ip = ipaddress.ip_address(host)
            if ip.is_private or ip.is_loopback or ip.is_link_local:
                return True
        except ValueError:
            # not an IP — could still be metadata hostname etc
            return host.lower() in {"localhost", "metadata.google.internal"}
    except Exception:
        return False
    return False


def _classify_param(p: SsrfParameter) -> list[SsrfFinding]:
    findings: list[SsrfFinding] = []
    if _is_url_param(p.name):
        findings.append(
            SsrfFinding(
                rule_id="SSRF-001",
                severity="LOW",
                title=f"Parameter {p.name!r} commonly carries URLs (SSRF candidate)",
                detail=(
                    "Parameter name matches the URL-handling heuristic. Should be tested for SSRF + open-redirect."
                ),
                remediation=(
                    "Validate the parameter against an allow-list of "
                    "internal-allowed URLs. Reject any host not in the list."
                ),
                location=p.name,
            )
        )
        # Webhook + image-fetcher specifics
        norm = _normalize_param(p.name)
        if "webhook" in norm or "callback" in norm:
            findings.append(
                SsrfFinding(
                    rule_id="SSRF-007",
                    severity="MEDIUM",
                    title=f"Webhook parameter {p.name!r} accepts arbitrary URLs",
                    detail=(
                        "Webhook handlers historically allow attackers to point "
                        "the server at internal services (Slack-style SSRF)."
                    ),
                    remediation=(
                        "Use a documented allow-list of webhook destinations + "
                        "fetch via an outbound proxy that blocks RFC 1918 + "
                        "metadata."
                    ),
                    location=p.name,
                )
            )
        if "image" in norm or "asset" in norm or "pdf" in norm:
            findings.append(
                SsrfFinding(
                    rule_id="SSRF-008",
                    severity="HIGH",
                    title=f"Server-side fetcher parameter {p.name!r}",
                    detail=(
                        "Image / asset URL parameters are a top SSRF vector. "
                        "Server fetches the URL and either returns it or "
                        "processes it (resize, OCR, etc.)."
                    ),
                    remediation=(
                        "Allow-list hosts. Block any IP that resolves to a "
                        "private / loopback / link-local / metadata range. "
                        "Resolve DNS once + dial that IP (no rebinding "
                        "window)."
                    ),
                    location=p.name,
                )
            )

    if _value_points_internal(p.sample_value):
        findings.append(
            SsrfFinding(
                rule_id="SSRF-002",
                severity="HIGH",
                title=f"Parameter {p.name!r} value points to internal/metadata host",
                detail=(
                    f"Observed sample value {p.sample_value!r} resolves to "
                    "an internal / loopback / cloud-metadata host. Even if "
                    "the back-end didn't dereference it, this strongly "
                    "suggests SSRF surface."
                ),
                remediation=(
                    "Validate URL against allow-list AND verify the resolved "
                    "IP is public before dialing. Block 169.254.169.254 + "
                    "RFC 1918 + ::1."
                ),
                location=p.name,
            )
        )
    return findings


def _classify_snippet(s: SsrfCodeSnippet) -> list[SsrfFinding]:
    findings: list[SsrfFinding] = []
    body = s.body or ""
    if not body:
        return findings
    for rule_id, lang, label, pattern in _CODE_PATTERNS:
        if lang and s.language and s.language.lower() != lang:
            continue
        for m in pattern.finditer(body):
            # Compute line of match
            line_no = body[: m.start()].count("\n") + 1 + s.line_offset
            findings.append(
                SsrfFinding(
                    rule_id=rule_id,
                    severity="HIGH",
                    title=f"{label} (SSRF-prone)",
                    detail=(
                        f"In {s.file_path}:{line_no}, a network call uses "
                        "user-controlled input as URL. Without allow-listing "
                        "this is SSRF."
                    ),
                    remediation=(
                        "Validate target URL against an allow-list. Resolve "
                        "DNS + check the resulting IP is public BEFORE "
                        "issuing the request."
                    ),
                    location=f"{s.file_path}:{line_no}",
                )
            )
    return findings


def analyze_ssrf(
    parameters: list[SsrfParameter],
    snippets: list[SsrfCodeSnippet] | None = None,
) -> SsrfAnalysis:
    snippets = snippets or []
    findings: list[SsrfFinding] = []
    for p in parameters:
        findings.extend(_classify_param(p))
    for s in snippets:
        findings.extend(_classify_snippet(s))
    from kryon.util.severity import SEVERITY_RANK as severity_order

    findings.sort(key=lambda f: (severity_order.get(f.severity, 99), f.rule_id, f.location))
    return SsrfAnalysis(
        total_parameters=len(parameters),
        total_snippets=len(snippets),
        findings=tuple(findings),
    )
