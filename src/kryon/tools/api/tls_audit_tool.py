"""F100 — agent-facing tool wrapper for the TLS profile auditor."""

from __future__ import annotations

import json
from typing import Any

from kryon.sdk.agents import function_tool
from kryon.tools.api.tls_audit import (
    TLSAnalysis,
    TLSCertificate,
    TLSFinding,
    TLSProfile,
    analyze_tls_profile,
)

__all__ = ["validate_tls_profile"]


def _finding_to_dict(f: TLSFinding) -> dict[str, Any]:
    return {
        "rule_id": f.rule_id,
        "severity": f.severity,
        "title": f.title,
        "detail": f.detail,
        "remediation": f.remediation,
    }


def _analysis_to_dict(a: TLSAnalysis) -> dict[str, Any]:
    by_severity: dict[str, int] = {}
    for f in a.findings:
        by_severity[f.severity] = by_severity.get(f.severity, 0) + 1
    return {
        "hostname": a.hostname,
        "finding_count": len(a.findings),
        "by_severity": by_severity,
        "findings": [_finding_to_dict(f) for f in a.findings],
    }


@function_tool
def validate_tls_profile(profile_json: str) -> str:
    """Static analysis of a TLS profile (handshake + certificate).

    Args:
        profile_json: JSON describing the TLS profile. Example shape:
            {
              "hostname": "example.com",
              "port": 443,
              "negotiated_protocol": "TLSv1.3",
              "supported_protocols": ["TLSv1.2", "TLSv1.3"],
              "negotiated_cipher": "TLS_AES_256_GCM_SHA384",
              "supported_ciphers": ["TLS_AES_256_GCM_SHA384", ...],
              "certificate": {
                "subject_common_name": "example.com",
                "issuer_common_name": "Let's Encrypt R13",
                "not_before": "2026-01-15T00:00:00Z",
                "not_after": "2026-04-15T00:00:00Z",
                "key_algorithm": "RSA",
                "key_size_bits": 2048,
                "signature_algorithm": "sha256WithRSAEncryption",
                "san_dns_names": ["example.com", "www.example.com"],
                "is_self_signed": false
              }
            }

    Returns:
        JSON summary with finding list sorted by severity.
    """
    if not profile_json.strip():
        return json.dumps({"error": "empty profile_json"})
    try:
        doc = json.loads(profile_json)
    except json.JSONDecodeError as e:
        return json.dumps({"error": f"invalid JSON: {e}"})
    if not isinstance(doc, dict):
        return json.dumps({"error": "profile_json must be a JSON object"})

    cert_dict = doc.get("certificate")
    cert: TLSCertificate | None = None
    if isinstance(cert_dict, dict):
        cert = TLSCertificate(
            subject_common_name=str(cert_dict.get("subject_common_name") or ""),
            issuer_common_name=str(cert_dict.get("issuer_common_name") or ""),
            not_before=str(cert_dict.get("not_before") or ""),
            not_after=str(cert_dict.get("not_after") or ""),
            key_algorithm=str(cert_dict.get("key_algorithm") or ""),
            key_size_bits=int(cert_dict.get("key_size_bits") or 0),
            signature_algorithm=str(cert_dict.get("signature_algorithm") or ""),
            san_dns_names=tuple(
                str(s) for s in (cert_dict.get("san_dns_names") or ())
            ),
            is_self_signed=bool(cert_dict.get("is_self_signed", False)),
            serial_number=str(cert_dict.get("serial_number") or ""),
        )

    profile = TLSProfile(
        hostname=str(doc.get("hostname") or ""),
        port=int(doc.get("port") or 443),
        negotiated_protocol=str(doc.get("negotiated_protocol") or ""),
        supported_protocols=tuple(
            str(p) for p in (doc.get("supported_protocols") or ())
        ),
        negotiated_cipher=str(doc.get("negotiated_cipher") or ""),
        supported_ciphers=tuple(
            str(c) for c in (doc.get("supported_ciphers") or ())
        ),
        certificate=cert,
    )
    analysis = analyze_tls_profile(profile)
    return json.dumps(_analysis_to_dict(analysis), ensure_ascii=False)
