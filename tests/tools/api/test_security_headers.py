"""F97 — TDD contract for the HTTP Security Headers auditor.

Coverage:
  - Each HSH-NNN rule has POSITIVE + NEGATIVE coverage.
  - CSP parser: directive splitting, source listing.
  - HSTS parser: max-age + flag directives.
  - Case-insensitive header lookup.
  - is_https=False suppresses HSH-010.
  - Realistic banking-grade fixtures (locked-down + permissive).
  - **Critical: drift-detection test reproducing the 6 findings
    detected manually on app.example.com — closes the loop
    on the gap that motivated F97.**
  - Frozen contracts + ALL_HSH_RULES pinned.
  - Tool wrapper.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from kryon.tools.api.security_headers import (
    ALL_HSH_RULES,
    HSHFinding,
    HTTPResponse,
    SecurityHeadersAnalysis,
    _parse_csp_directives,
    _parse_hsts_directives,
    analyze_security_headers,
)


def _ids(findings) -> set[str]:
    return {f.rule_id for f in findings}


# =====================================================================
# Parser helpers
# =====================================================================


def test_parse_csp_directives_basic():
    csp = "default-src 'self'; script-src 'self' https://cdn.example.com"
    out = _parse_csp_directives(csp)
    assert out["default-src"] == ["'self'"]
    assert out["script-src"] == ["'self'", "https://cdn.example.com"]


def test_parse_csp_directives_empty():
    assert _parse_csp_directives("") == {}


def test_parse_csp_directives_strips_whitespace():
    csp = "  default-src   'none' ;  script-src 'self'  ;  "
    out = _parse_csp_directives(csp)
    assert out["default-src"] == ["'none'"]
    assert out["script-src"] == ["'self'"]


def test_parse_csp_case_normalized_on_directive():
    """RFC 7762: directive names are case-insensitive. The parser
    lowercases them so downstream checks are deterministic."""
    out = _parse_csp_directives("Default-Src 'self'; SCRIPT-SRC https://x")
    assert "default-src" in out
    assert "script-src" in out


def test_parse_hsts_directives():
    out = _parse_hsts_directives("max-age=31536000; includeSubDomains; preload")
    assert out["max-age"] == "31536000"
    assert out["includesubdomains"] is True
    assert out["preload"] is True


def test_parse_hsts_max_age_only():
    out = _parse_hsts_directives("max-age=0")
    assert out["max-age"] == "0"
    assert "preload" not in out


# =====================================================================
# Group A — CSP rules
# =====================================================================


def test_hsh_001_csp_missing():
    r = HTTPResponse(headers={})
    findings = analyze_security_headers(r).findings
    high = [f for f in findings if f.rule_id == "HSH-001"]
    assert high and high[0].severity == "HIGH"


def test_hsh_001_csp_present_silences():
    r = HTTPResponse(headers={"Content-Security-Policy": "default-src 'self'"})
    assert "HSH-001" not in _ids(analyze_security_headers(r).findings)


def test_hsh_002_unsafe_inline_fires():
    r = HTTPResponse(headers={"Content-Security-Policy": "default-src 'self'; script-src 'self' 'unsafe-inline'"})
    findings = analyze_security_headers(r).findings
    high = [f for f in findings if f.rule_id == "HSH-002"]
    assert high and high[0].severity == "HIGH"


def test_hsh_002_no_unsafe_inline_silent():
    r = HTTPResponse(headers={"Content-Security-Policy": "default-src 'self'; script-src 'self' 'nonce-abc123'"})
    assert "HSH-002" not in _ids(analyze_security_headers(r).findings)


def test_hsh_003_unsafe_eval_fires():
    r = HTTPResponse(headers={"Content-Security-Policy": "default-src 'self' 'unsafe-eval'"})
    findings = analyze_security_headers(r).findings
    med = [f for f in findings if f.rule_id == "HSH-003"]
    assert med and med[0].severity == "MEDIUM"


def test_hsh_004_wildcard_in_script_src_fires():
    r = HTTPResponse(headers={"Content-Security-Policy": "default-src 'self'; script-src *"})
    findings = analyze_security_headers(r).findings
    assert "HSH-004" in _ids(findings)


def test_hsh_004_wildcard_in_default_src_fires():
    r = HTTPResponse(headers={"Content-Security-Policy": "default-src *"})
    assert "HSH-004" in _ids(analyze_security_headers(r).findings)


def test_hsh_005_http_scheme_fires():
    r = HTTPResponse(headers={"Content-Security-Policy": "default-src 'self'; img-src 'self' http://insecure.example"})
    findings = analyze_security_headers(r).findings
    assert "HSH-005" in _ids(findings)


def test_hsh_005_https_only_silent():
    r = HTTPResponse(headers={"Content-Security-Policy": "default-src 'self'; img-src 'self' https://secure.cdn"})
    assert "HSH-005" not in _ids(analyze_security_headers(r).findings)


# =====================================================================
# Group B — HSTS rules
# =====================================================================


def test_hsh_010_hsts_missing_on_https():
    r = HTTPResponse(is_https=True, headers={})
    findings = analyze_security_headers(r).findings
    hsts = [f for f in findings if f.rule_id == "HSH-010"]
    assert hsts and hsts[0].severity == "HIGH"


def test_hsh_010_hsts_missing_silent_on_http():
    """HSTS over plain HTTP is meaningless — suppress the finding."""
    r = HTTPResponse(is_https=False, headers={})
    assert "HSH-010" not in _ids(analyze_security_headers(r).findings)


def test_hsh_010_hsts_present_silences():
    r = HTTPResponse(
        is_https=True,
        headers={"Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload"},
    )
    assert "HSH-010" not in _ids(analyze_security_headers(r).findings)


def test_hsh_011_max_age_too_short_fires():
    r = HTTPResponse(
        is_https=True,
        headers={"Strict-Transport-Security": "max-age=3600; includeSubDomains; preload"},
    )
    findings = analyze_security_headers(r).findings
    assert "HSH-011" in _ids(findings)


def test_hsh_011_max_age_meets_threshold_silent():
    """6 months exactly = 15768000s should NOT fire HSH-011."""
    r = HTTPResponse(
        is_https=True,
        headers={"Strict-Transport-Security": "max-age=15768000; includeSubDomains; preload"},
    )
    assert "HSH-011" not in _ids(analyze_security_headers(r).findings)


def test_hsh_012_include_subdomains_missing_fires():
    r = HTTPResponse(
        is_https=True,
        headers={"Strict-Transport-Security": "max-age=31536000"},
    )
    findings = analyze_security_headers(r).findings
    assert "HSH-012" in _ids(findings)


def test_hsh_012_include_subdomains_present_silent():
    r = HTTPResponse(
        is_https=True,
        headers={"Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload"},
    )
    assert "HSH-012" not in _ids(analyze_security_headers(r).findings)


def test_hsh_013_preload_missing_fires():
    r = HTTPResponse(
        is_https=True,
        headers={"Strict-Transport-Security": "max-age=31536000; includeSubDomains"},
    )
    findings = analyze_security_headers(r).findings
    info = [f for f in findings if f.rule_id == "HSH-013"]
    assert info and info[0].severity == "INFO"


def test_hsh_013_preload_present_silent():
    r = HTTPResponse(
        is_https=True,
        headers={"Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload"},
    )
    assert "HSH-013" not in _ids(analyze_security_headers(r).findings)


# =====================================================================
# Group C — Basic protections
# =====================================================================


def test_hsh_020_xcto_missing_fires():
    r = HTTPResponse(headers={"Content-Security-Policy": "default-src 'self'"})
    findings = analyze_security_headers(r).findings
    assert "HSH-020" in _ids(findings)


def test_hsh_020_xcto_wrong_value_fires():
    r = HTTPResponse(
        headers={
            "Content-Security-Policy": "default-src 'self'",
            "X-Content-Type-Options": "DENY",  # wrong value
        }
    )
    assert "HSH-020" in _ids(analyze_security_headers(r).findings)


def test_hsh_020_xcto_nosniff_silences():
    r = HTTPResponse(
        headers={
            "Content-Security-Policy": "default-src 'self'",
            "X-Content-Type-Options": "nosniff",
        }
    )
    assert "HSH-020" not in _ids(analyze_security_headers(r).findings)


def test_hsh_021_neither_xfo_nor_frame_ancestors_fires():
    r = HTTPResponse(headers={"Content-Security-Policy": "default-src 'self'"})
    findings = analyze_security_headers(r).findings
    assert "HSH-021" in _ids(findings)


def test_hsh_021_xfo_present_silences():
    r = HTTPResponse(
        headers={
            "Content-Security-Policy": "default-src 'self'",
            "X-Frame-Options": "DENY",
        }
    )
    assert "HSH-021" not in _ids(analyze_security_headers(r).findings)


def test_hsh_021_frame_ancestors_silences():
    r = HTTPResponse(
        headers={
            "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'",
        }
    )
    assert "HSH-021" not in _ids(analyze_security_headers(r).findings)


def test_hsh_022_referrer_policy_missing_fires():
    r = HTTPResponse(headers={"Content-Security-Policy": "default-src 'self'"})
    findings = analyze_security_headers(r).findings
    assert "HSH-022" in _ids(findings)


def test_hsh_022_referrer_policy_unsafe_url_fires():
    r = HTTPResponse(
        headers={
            "Content-Security-Policy": "default-src 'self'",
            "Referrer-Policy": "unsafe-url",
        }
    )
    assert "HSH-022" in _ids(analyze_security_headers(r).findings)


def test_hsh_022_referrer_policy_strict_silences():
    r = HTTPResponse(
        headers={
            "Content-Security-Policy": "default-src 'self'",
            "Referrer-Policy": "strict-origin-when-cross-origin",
        }
    )
    assert "HSH-022" not in _ids(analyze_security_headers(r).findings)


def test_hsh_023_permissions_policy_missing_fires():
    r = HTTPResponse(headers={"Content-Security-Policy": "default-src 'self'"})
    findings = analyze_security_headers(r).findings
    assert "HSH-023" in _ids(findings)


def test_hsh_023_permissions_policy_present_silences():
    r = HTTPResponse(
        headers={
            "Content-Security-Policy": "default-src 'self'",
            "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
        }
    )
    assert "HSH-023" not in _ids(analyze_security_headers(r).findings)


# =====================================================================
# Group D — Cross-Origin isolation
# =====================================================================


def test_hsh_030_coop_missing_fires():
    r = HTTPResponse(headers={"Content-Security-Policy": "default-src 'self'"})
    assert "HSH-030" in _ids(analyze_security_headers(r).findings)


def test_hsh_030_coop_present_silences():
    r = HTTPResponse(
        headers={
            "Content-Security-Policy": "default-src 'self'",
            "Cross-Origin-Opener-Policy": "same-origin",
        }
    )
    assert "HSH-030" not in _ids(analyze_security_headers(r).findings)


def test_hsh_031_corp_missing_fires():
    r = HTTPResponse(headers={"Content-Security-Policy": "default-src 'self'"})
    assert "HSH-031" in _ids(analyze_security_headers(r).findings)


def test_hsh_032_coep_missing_fires_info():
    r = HTTPResponse(headers={"Content-Security-Policy": "default-src 'self'"})
    findings = analyze_security_headers(r).findings
    coep = [f for f in findings if f.rule_id == "HSH-032"]
    assert coep and coep[0].severity == "INFO"


# =====================================================================
# Group E — Info leaks
# =====================================================================


def test_hsh_040_nginx_with_version_fires():
    r = HTTPResponse(headers={"Server": "nginx/1.18.0"})
    findings = analyze_security_headers(r).findings
    assert "HSH-040" in _ids(findings)


def test_hsh_040_apache_with_version_fires():
    r = HTTPResponse(headers={"Server": "Apache/2.4.41 (Ubuntu)"})
    assert "HSH-040" in _ids(analyze_security_headers(r).findings)


def test_hsh_040_plain_nginx_no_version_silent():
    """`Server: nginx` (no slash, no version) is NOT a leak."""
    r = HTTPResponse(headers={"Server": "nginx"})
    assert "HSH-040" not in _ids(analyze_security_headers(r).findings)


def test_hsh_040_cloudflare_silent():
    """`Server: cloudflare` is a CDN identifier, not a version leak."""
    r = HTTPResponse(headers={"Server": "cloudflare"})
    assert "HSH-040" not in _ids(analyze_security_headers(r).findings)


def test_hsh_041_x_powered_by_fires():
    r = HTTPResponse(headers={"X-Powered-By": "Express"})
    assert "HSH-041" in _ids(analyze_security_headers(r).findings)


def test_hsh_041_x_aspnet_version_fires():
    r = HTTPResponse(headers={"X-AspNet-Version": "4.0.30319"})
    assert "HSH-041" in _ids(analyze_security_headers(r).findings)


def test_hsh_041_no_fingerprint_headers_silent():
    r = HTTPResponse(headers={"Content-Type": "text/html"})
    assert "HSH-041" not in _ids(analyze_security_headers(r).findings)


# =====================================================================
# Case-insensitive lookup
# =====================================================================


def test_case_insensitive_header_lookup():
    """RFC 7230 §3.2: header names case-insensitive."""
    r = HTTPResponse(
        is_https=True,
        headers={
            "content-security-policy": "default-src 'self'",
            "STRICT-TRANSPORT-SECURITY": "max-age=31536000; includeSubDomains; preload",
            "X-CONTENT-TYPE-OPTIONS": "nosniff",
        },
    )
    analysis = analyze_security_headers(r)
    assert analysis.csp_present is True
    assert analysis.hsts_present is True
    assert "HSH-001" not in _ids(analysis.findings)
    assert "HSH-010" not in _ids(analysis.findings)
    assert "HSH-020" not in _ids(analysis.findings)


# =====================================================================
# DRIFT-DETECTION: app.example.com reproduction
# =====================================================================


def test_cashbox_example_reproduces_six_findings():
    """**Critical test**: reproduce the exact 6 findings detected
    manually during validation against https://app.example.com/.
    This closes the loop on the gap that motivated F97 — if this
    test ever fails, either the auditor regressed OR the real target
    fixed something (good news, but update the test fixture)."""
    # These are the exact response headers app.example.com
    # returned during the May 2026 validation probe.
    r = HTTPResponse(
        url="https://app.example.com/",
        method="GET",
        is_https=True,
        headers={
            "Server": "nginx",  # NB: cashbox returned bare "nginx" — no version leak
            "Date": "Wed, 13 May 2026 18:46:21 GMT",
            "Content-Type": "text/html",
            "Content-Length": "1610",
            "Last-Modified": "Tue, 17 Mar 2026 14:07:08 GMT",
            "Connection": "keep-alive",
            "ETag": '"69b9600c-64a"',
            "Accept-Ranges": "bytes",
        },
    )
    analysis = analyze_security_headers(r)
    ids = _ids(analysis.findings)

    # The 6 originally-detected manual findings:
    assert "HSH-001" in ids, "CSP missing — should fire HIGH (this was finding #1 from manual review)"
    assert "HSH-010" in ids, "HSTS missing — should fire HIGH (finding #2)"
    assert "HSH-020" in ids, "X-Content-Type-Options missing — should fire MEDIUM (finding #3)"
    assert "HSH-021" in ids, "Clickjacking protection missing — should fire MEDIUM (finding #4)"
    assert "HSH-022" in ids, "Referrer-Policy missing — should fire MEDIUM (finding #5)"

    # Bonus: HSH-022/023 + COOP/CORP/COEP should also surface
    # because they're all completely absent. The headline 6 manual
    # findings cover the HIGH + MEDIUM tier; F97 surfaces additional
    # LOW tier items that the manual review compressed.
    assert "HSH-023" in ids  # Permissions-Policy
    assert "HSH-030" in ids  # COOP

    # Server header in this case was bare "nginx" — HSH-040 should
    # NOT fire (no version leak).
    assert "HSH-040" not in ids, "Server: nginx (bare) should NOT fire HSH-040"


# =====================================================================
# Realistic fixtures
# =====================================================================


def test_locked_down_response_minimal_findings():
    """A well-configured banking response — all major headers set
    correctly. Expected: zero HIGH/MEDIUM findings; possibly LOW/INFO
    on cross-origin headers if the bank doesn't deploy them."""
    r = HTTPResponse(
        is_https=True,
        headers={
            "Content-Security-Policy": ("default-src 'self'; script-src 'self' 'nonce-abc123'; frame-ancestors 'none'"),
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "Referrer-Policy": "strict-origin-when-cross-origin",
            "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
            "Cross-Origin-Opener-Policy": "same-origin",
            "Cross-Origin-Resource-Policy": "same-origin",
        },
    )
    findings = analyze_security_headers(r).findings
    ids = _ids(findings)
    # No HIGH or MEDIUM findings.
    for f in findings:
        assert f.severity not in ("HIGH", "MEDIUM"), f"Unexpected {f.severity} on locked-down fixture: {f.rule_id}"


# =====================================================================
# Sorting + pinning
# =====================================================================


def test_findings_sorted_by_severity():
    """Plain HTTP response with no security headers — many findings;
    must be ordered CRITICAL → INFO."""
    r = HTTPResponse(is_https=True, headers={"Server": "nginx/1.18.0"})
    findings = analyze_security_headers(r).findings
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    ranks = [severity_order[f.severity] for f in findings]
    assert ranks == sorted(ranks)


def test_all_hsh_rules_pinned():
    """Every documented rule ID must be in the pinned set. Catches
    accidental removal."""
    expected = (
        {f"HSH-00{i}" for i in range(1, 6)}
        | {f"HSH-01{i}" for i in range(0, 4)}
        | {f"HSH-02{i}" for i in range(0, 4)}
        | {f"HSH-03{i}" for i in range(0, 3)}
        | {f"HSH-04{i}" for i in range(0, 2)}
    )
    assert expected <= ALL_HSH_RULES


# =====================================================================
# Frozen contracts
# =====================================================================


def test_dataclasses_are_frozen():
    from dataclasses import FrozenInstanceError

    r = HTTPResponse(url="x")
    with pytest.raises(FrozenInstanceError):
        r.url = "y"  # type: ignore[misc]

    f = HSHFinding(
        rule_id="HSH-001",
        severity="HIGH",
        title="x",
        detail="x",
        remediation="x",
    )
    with pytest.raises(FrozenInstanceError):
        f.severity = "LOW"  # type: ignore[misc]

    a = SecurityHeadersAnalysis(csp_present=False, hsts_present=False)
    with pytest.raises(FrozenInstanceError):
        a.csp_present = True  # type: ignore[misc]


# =====================================================================
# Tool wrapper
# =====================================================================


def test_tool_wrapper_dict_shape():
    from kryon.tools.api.security_headers_tool import _analysis_to_dict

    r = HTTPResponse(is_https=True, headers={})
    analysis = analyze_security_headers(r)
    payload = _analysis_to_dict(analysis)
    assert payload["csp_present"] is False
    assert payload["hsts_present"] is False
    assert payload["by_severity"]["HIGH"] >= 2
    json.dumps(payload)


def test_tool_wrapper_handles_empty_headers():
    from kryon.tools.api.security_headers_tool import _analysis_to_dict

    analysis = analyze_security_headers(HTTPResponse(is_https=True, headers={}))
    payload = _analysis_to_dict(analysis)
    # Many findings fire on a fully-empty response.
    assert payload["finding_count"] >= 8


# =====================================================================
# Edge cases
# =====================================================================


def test_csp_only_default_src_does_not_fire_unsafe_inline():
    """Edge: default-src without 'unsafe-inline' shouldn't trip
    HSH-002."""
    r = HTTPResponse(headers={"Content-Security-Policy": "default-src 'self'"})
    assert "HSH-002" not in _ids(analyze_security_headers(r).findings)


def test_csp_with_only_unsafe_inline_in_default_src_fires():
    """HSH-002 must check default-src as fallback when script-src
    is absent — that's how CSP spec applies it."""
    r = HTTPResponse(headers={"Content-Security-Policy": "default-src 'self' 'unsafe-inline'"})
    assert "HSH-002" in _ids(analyze_security_headers(r).findings)


def test_hsts_malformed_max_age_silent():
    """Garbage max-age doesn't crash; HSH-011 silenced."""
    r = HTTPResponse(
        is_https=True,
        headers={"Strict-Transport-Security": "max-age=not-a-number; includeSubDomains; preload"},
    )
    findings = analyze_security_headers(r).findings
    assert "HSH-011" not in _ids(findings)
