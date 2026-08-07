"""PSD2 RTS finding->control mapper + FAPI 1.0 Advanced bridge."""

from __future__ import annotations

from kryon.compliance import map_findings_to_framework
from kryon.compliance.psd2 import (
    PSD2_CONTROLS,
    fapi_report_to_findings,
    map_finding_to_psd2_controls,
)
from kryon.intelligence.models import Finding, Severity
from kryon.tools.api.fapi_validator import parse_discovery, validate_fapi_advanced


def _f(title: str, description: str = "", severity: str = "high") -> Finding:
    return Finding(
        title=title,
        description=description,
        severity=Severity(severity),
        affected_asset="bank.example",
    )


# --- keyword mapper ---


def test_maps_tls_finding_to_secure_communication():
    assert "RTS-Art35" in map_finding_to_psd2_controls(_f("Weak TLS 1.0 accepted on token endpoint"))


def test_maps_sca_finding_to_strong_customer_auth():
    ctrls = map_finding_to_psd2_controls(_f("MFA not enforced", "authentication bypass possible"))
    assert "RTS-Art4" in ctrls


def test_maps_fapi_finding_to_secure_open_standard():
    assert "RTS-Art30" in map_finding_to_psd2_controls(_f("FAPI PKCE S256 missing"))


def test_unrelated_finding_maps_to_nothing():
    assert map_finding_to_psd2_controls(_f("printer out of toner")) == []


def test_no_finding_ever_maps_to_a_manual_control():
    manual_ids = {c.id for c in PSD2_CONTROLS if c.verdict_mode == "manual"}
    assert manual_ids  # sanity: there ARE manual controls
    probes = [
        "weak tls",
        "mfa bypass sca",
        "fapi pkce implicit flow",
        "dpop token replay sender-constrained",
        "ps256 es256 credential signing jarm",
        "dynamic linking par request object",
        "incident breach license exemption fraud transaction monitoring",
    ]
    for title in probes:
        for cid in map_finding_to_psd2_controls(_f(title)):
            assert cid not in manual_ids, f"{title!r} leaked into manual control {cid}"


# --- FAPI bridge ---


def test_fapi_bridge_converts_failing_report_to_findings():
    # An empty discovery doc fails every CRITICAL/HIGH FAPI check.
    report = validate_fapi_advanced(parse_discovery({"issuer": "https://bank.example"}))
    findings = fapi_report_to_findings(report)
    assert findings
    assert all(f.tool_source == "fapi_validator" for f in findings)


def test_fapi_bridge_findings_light_up_the_right_rts_controls():
    report = validate_fapi_advanced(parse_discovery({"issuer": "https://bank.example"}))
    mapped: set[str] = set()
    for f in fapi_report_to_findings(report):
        mapped.update(map_finding_to_psd2_controls(f))
    assert "RTS-Art4" in mapped  # FAPI-10 SCA ACR/AMR
    assert "RTS-Art5" in mapped  # FAPI-1 PAR / dynamic linking
    assert "RTS-Art30" in mapped  # every FAPI gap implies the secure-standard


def test_compliant_discovery_yields_no_findings():
    compliant = {
        "issuer": "https://bank.example",
        "pushed_authorization_request_endpoint": "https://bank.example/par",
        "request_object_signing_alg_values_supported": ["PS256"],
        "id_token_signing_alg_values_supported": ["PS256"],
        "token_endpoint_auth_methods_supported": ["private_key_jwt"],
        "tls_client_certificate_bound_access_tokens": True,
        "code_challenge_methods_supported": ["S256"],
        "response_types_supported": ["code"],
        "response_modes_supported": ["jwt"],
        "acr_values_supported": ["urn:openbanking:psd2:sca"],
    }
    report = validate_fapi_advanced(parse_discovery(compliant))
    # Only non-pass checks become findings; a fully compliant AS => none.
    non_pass = [r for r in report.results if r.status not in ("pass", "inapplicable")]
    assert len(fapi_report_to_findings(report)) == len(non_pass)


# --- registry integration ---


def test_registered_via_framework_map():
    findings = [_f("Weak TLS on token endpoint"), _f("No SCA / MFA enforced")]
    report = map_findings_to_framework(findings, "psd2")
    assert "PSD2" in report.framework
    # the `fapi` alias resolves to the same module
    assert map_findings_to_framework(findings, "fapi").framework == report.framework
