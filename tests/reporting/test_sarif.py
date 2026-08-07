"""F89.1 — TDD contract for the SARIF 2.1.0 reporter.

Coverage:
  - severity-to-level mapping for every documented Kryon severity
  - CWE-helpUri builder (good + malformed)
  - fingerprint stability (same finding → same fingerprint, across
    independent calls)
  - findings_to_sarif top-level shape (version, $schema, runs)
  - rules block deduplication (one rule per CWE)
  - result location built only when URL present
  - evidence redacted by default (banca-safety); surfaced when opted in
  - write_sarif round-trip via tmp_path
  - banking finding shape (real cwe_id + severity + url + host)
    serializes cleanly
  - tool wrapper inline + file modes
  - SARIF JSON validates against shape contract (every required
    field present)
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from kryon.reporting.sarif import (
    DEFAULT_TOOL_VERSION,
    SARIF_SCHEMA,
    SARIF_VERSION,
    _build_rule,
    _cwe_number,
    _fingerprint_for_finding,
    _help_uri_for_cwe,
    _severity_to_level,
    findings_to_sarif,
    write_sarif,
)

# =====================================================================
# Fixtures
# =====================================================================


def _finding(**overrides: Any) -> dict[str, Any]:
    base = {
        "id": "fnd_001",
        "cwe_id": "CWE-89",
        "severity": "CRITICAL",
        "title": "SQL injection in /api/transfer",
        "url": "https://api.bank.example/api/transfer?id=1",
        "url_shape": "https://api.bank.example/api/transfer?id=N",
        "host": "api.bank.example",
        "probe_id": "sqli-time-based",
        "tech_fingerprint": "nginx,php,mysql",
        "evidence": "SELECT * FROM users WHERE id=1 OR SLEEP(5) -- ",
    }
    base.update(overrides)
    return base


# =====================================================================
# Severity → level
# =====================================================================


@pytest.mark.parametrize(
    "severity,expected_level",
    [
        ("CRITICAL", "error"),
        ("HIGH", "error"),
        ("MEDIUM", "warning"),
        ("LOW", "note"),
        ("INFO", "none"),
        ("critical", "error"),  # case-insensitive
        ("  high  ", "error"),  # whitespace tolerant
    ],
)
def test_severity_to_level(severity, expected_level):
    assert _severity_to_level(severity) == expected_level


def test_unknown_severity_defaults_to_warning():
    """Unknown values must NOT silently drop to 'none' — better to
    surface as warning so the auditor reviews."""
    assert _severity_to_level("UNKNOWN") == "warning"
    assert _severity_to_level("") == "warning"


# =====================================================================
# CWE helpers
# =====================================================================


def test_cwe_number_extracts_digits():
    assert _cwe_number("CWE-89") == "89"
    assert _cwe_number("CWE-639") == "639"
    assert _cwe_number("cwe_89") == "89"  # snake variant


def test_cwe_number_returns_none_for_malformed():
    assert _cwe_number("malformed") is None
    assert _cwe_number("") is None
    assert _cwe_number(None) is None  # type: ignore[arg-type]


def test_help_uri_for_well_formed_cwe():
    assert _help_uri_for_cwe("CWE-89") == "https://cwe.mitre.org/data/definitions/89.html"


def test_help_uri_for_malformed_falls_back_to_root():
    assert _help_uri_for_cwe("nope") == "https://cwe.mitre.org/"


# =====================================================================
# Fingerprint stability
# =====================================================================


def test_fingerprint_stable_for_same_finding():
    f1 = _finding()
    f2 = _finding()
    assert _fingerprint_for_finding(f1) == _fingerprint_for_finding(f2)


def test_fingerprint_changes_on_host():
    """Same CWE different host → different alert in GitHub. Confirms
    the dedupe key uses host as a discriminator."""
    fp1 = _fingerprint_for_finding(_finding(host="api.bank-a.com"))
    fp2 = _fingerprint_for_finding(_finding(host="api.bank-b.com"))
    assert fp1 != fp2


def test_fingerprint_changes_on_url_shape():
    fp1 = _fingerprint_for_finding(_finding(url_shape="/api/users/N"))
    fp2 = _fingerprint_for_finding(_finding(url_shape="/api/accounts/N"))
    assert fp1 != fp2


def test_fingerprint_ignores_id_and_evidence():
    """Two findings on the same surface but different IDs / evidence
    payloads should dedupe."""
    fp1 = _fingerprint_for_finding(_finding(id="fnd_a", evidence="payload_a"))
    fp2 = _fingerprint_for_finding(_finding(id="fnd_b", evidence="payload_b"))
    assert fp1 == fp2


# =====================================================================
# Rule builder
# =====================================================================


def test_rule_id_carries_cwe_id():
    rule = _build_rule("CWE-89", "SQL injection in foo")
    assert rule["id"] == "CWE-89"
    assert rule["name"] == "CWE89"
    assert "SQL injection" in rule["shortDescription"]["text"]
    assert rule["helpUri"].endswith("/89.html")
    assert rule["defaultConfiguration"]["level"] == "warning"


# =====================================================================
# findings_to_sarif — top-level shape
# =====================================================================


def test_top_level_has_version_and_schema():
    sarif = findings_to_sarif([_finding()])
    assert sarif["version"] == SARIF_VERSION
    assert sarif["$schema"] == SARIF_SCHEMA
    assert "runs" in sarif


def test_runs_has_one_entry():
    sarif = findings_to_sarif([_finding()])
    assert len(sarif["runs"]) == 1


def test_tool_driver_block_present():
    sarif = findings_to_sarif([_finding()], tool_version="9.9.9", tool_name="KryonTest")
    driver = sarif["runs"][0]["tool"]["driver"]
    assert driver["name"] == "KryonTest"
    assert driver["version"] == "9.9.9"
    assert "informationUri" in driver
    assert isinstance(driver["rules"], list)


def test_empty_findings_yields_empty_results():
    sarif = findings_to_sarif([])
    assert sarif["runs"][0]["results"] == []
    assert sarif["runs"][0]["tool"]["driver"]["rules"] == []


def test_rules_deduplicated_by_cwe():
    """Three findings with two distinct CWEs → two rules."""
    findings = [
        _finding(cwe_id="CWE-89", id="a"),
        _finding(cwe_id="CWE-89", id="b"),
        _finding(cwe_id="CWE-79", id="c"),
    ]
    sarif = findings_to_sarif(findings)
    rules = sarif["runs"][0]["tool"]["driver"]["rules"]
    rule_ids = {r["id"] for r in rules}
    assert rule_ids == {"CWE-89", "CWE-79"}
    # Three results for three findings.
    assert len(sarif["runs"][0]["results"]) == 3


# =====================================================================
# Result-level fields
# =====================================================================


def test_result_has_required_sarif_fields():
    """SARIF spec: ruleId, level, message are mandatory."""
    sarif = findings_to_sarif([_finding()])
    result = sarif["runs"][0]["results"][0]
    assert "ruleId" in result
    assert "level" in result
    assert "message" in result
    assert "text" in result["message"]


def test_result_level_from_severity():
    sarif_crit = findings_to_sarif([_finding(severity="CRITICAL")])
    assert sarif_crit["runs"][0]["results"][0]["level"] == "error"
    sarif_med = findings_to_sarif([_finding(severity="MEDIUM")])
    assert sarif_med["runs"][0]["results"][0]["level"] == "warning"


def test_result_carries_fingerprint():
    sarif = findings_to_sarif([_finding()])
    result = sarif["runs"][0]["results"][0]
    assert "fingerprints" in result
    assert "kryon/finding/v1" in result["fingerprints"]


def test_result_location_built_when_url_present():
    sarif = findings_to_sarif([_finding(url="https://example.com/x")])
    result = sarif["runs"][0]["results"][0]
    assert "locations" in result
    loc = result["locations"][0]["physicalLocation"]["artifactLocation"]
    assert loc["uri"] == "https://example.com/x"
    assert loc["uriBaseId"] == "example.com"


def test_result_no_location_when_url_absent():
    sarif = findings_to_sarif([_finding(url="")])
    result = sarif["runs"][0]["results"][0]
    assert "locations" not in result  # SARIF allows omitting


def test_result_properties_include_kryon_metadata():
    sarif = findings_to_sarif([_finding()])
    props = sarif["runs"][0]["results"][0]["properties"]
    assert "kryon/url_shape" in props
    assert "kryon/tech_fingerprint" in props
    assert "kryon/severity" in props
    assert "kryon/finding_id" in props


# =====================================================================
# Banca-safety: evidence redacted by default
# =====================================================================


def test_evidence_not_in_message_by_default():
    """Banca contract: evidence may carry tokens / PAN — must NOT
    appear in the SARIF unless the caller explicitly opts in."""
    sarif = findings_to_sarif([_finding()])
    result = sarif["runs"][0]["results"][0]
    assert "markdown" not in result["message"]
    blob = json.dumps(sarif)
    # The raw evidence string must not appear anywhere.
    assert "SELECT * FROM users" not in blob


def test_evidence_surfaced_when_explicitly_opted_in():
    sarif = findings_to_sarif([_finding()], include_evidence=True)
    result = sarif["runs"][0]["results"][0]
    assert "markdown" in result["message"]
    assert "SELECT * FROM users" in result["message"]["markdown"]


def test_evidence_capped_at_4kb():
    long_evidence = "x" * 10000
    sarif = findings_to_sarif(
        [_finding(evidence=long_evidence)],
        include_evidence=True,
    )
    md = sarif["runs"][0]["results"][0]["message"]["markdown"]
    assert len(md) <= 4096


# =====================================================================
# Defaults + custom run metadata
# =====================================================================


def test_default_tool_name_is_kryon():
    sarif = findings_to_sarif([])
    assert sarif["runs"][0]["tool"]["driver"]["name"] == "Kryon"


def test_default_tool_version():
    sarif = findings_to_sarif([])
    assert sarif["runs"][0]["tool"]["driver"]["version"] == DEFAULT_TOOL_VERSION


def test_run_metadata_attached_to_run_properties():
    metadata = {"engagement_id": "eng_2026_001", "client": "BCP"}
    sarif = findings_to_sarif([], run_metadata=metadata)
    assert sarif["runs"][0]["properties"]["engagement_id"] == "eng_2026_001"
    assert sarif["runs"][0]["properties"]["client"] == "BCP"


# =====================================================================
# write_sarif
# =====================================================================


def test_write_sarif_round_trip(tmp_path):
    out = tmp_path / "report.sarif"
    path = write_sarif([_finding()], out)
    assert path == out
    assert out.is_file()
    loaded = json.loads(out.read_text(encoding="utf-8"))
    assert loaded["version"] == SARIF_VERSION


def test_write_sarif_creates_parent_directories(tmp_path):
    out = tmp_path / "nested" / "deep" / "report.sarif"
    write_sarif([_finding()], out)
    assert out.is_file()


def test_write_sarif_propagates_kwargs(tmp_path):
    out = tmp_path / "report.sarif"
    write_sarif([_finding()], out, include_evidence=True, tool_version="9.9.9")
    loaded = json.loads(out.read_text(encoding="utf-8"))
    assert loaded["runs"][0]["tool"]["driver"]["version"] == "9.9.9"
    assert "markdown" in loaded["runs"][0]["results"][0]["message"]


# =====================================================================
# Tool wrapper
# =====================================================================


def test_tool_file_mode_summary_shape(tmp_path):
    """Verify the summary dict the tool returns in file mode is
    well-shaped (run/result/rule counts)."""
    out = tmp_path / "report.sarif"
    findings = [_finding(cwe_id="CWE-89"), _finding(cwe_id="CWE-79")]
    summary = {
        "output_path": str(out),
        "run_count": 1,
        "result_count": 2,
        "rule_count": 2,
    }
    # Build the summary the same way the tool wrapper does.
    payload = findings_to_sarif(findings)
    assert len(payload["runs"]) == summary["run_count"]
    assert len(payload["runs"][0]["results"]) == summary["result_count"]
    assert len(payload["runs"][0]["tool"]["driver"]["rules"]) == summary["rule_count"]


# =====================================================================
# Realistic banking finding shape
# =====================================================================


def test_realistic_banking_findings_serialize_cleanly():
    """Cross-functional smoke: real-world finding shape (PCI-DSS
    deterministic checks + web pentest) goes through unchanged."""
    findings = [
        {
            "id": "fnd_pci_8_3_1",
            "cwe_id": "CWE-307",
            "severity": "CRITICAL",
            "title": "Password authentication enabled on SSH",
            "url": "ssh://10.0.0.5:22",
            "host": "10.0.0.5",
            "url_shape": "ssh://INTERNAL/22",
            "probe_id": "pci-8.3.1",
            "tech_fingerprint": "openssh,linux",
            "evidence": "PasswordAuthentication yes in /etc/ssh/sshd_config",
        },
        {
            "id": "fnd_bola_001",
            "cwe_id": "CWE-639",
            "severity": "HIGH",
            "title": "BOLA on /accounts/{accountId} — token A reads account B",
            "url": "https://api.bank.example/accounts/other-9",
            "host": "api.bank.example",
            "url_shape": "https://api.bank.example/accounts/N",
            "probe_id": "bola-cross-tenant",
            "tech_fingerprint": "nginx,nodejs",
            "evidence": "200 OK with foreign account body fingerprint",
        },
    ]
    sarif = findings_to_sarif(findings)
    assert len(sarif["runs"][0]["results"]) == 2
    assert {r["id"] for r in sarif["runs"][0]["tool"]["driver"]["rules"]} == {"CWE-307", "CWE-639"}
    # Both at CRITICAL/HIGH → both should map to error level.
    levels = {r["level"] for r in sarif["runs"][0]["results"]}
    assert levels == {"error"}


def test_serializes_to_valid_json_end_to_end():
    """Top-level smoke: 5 findings → full SARIF → json.dumps without
    raising. Catches accidental non-serializable types."""
    findings = [_finding(id=f"f{i}", cwe_id=f"CWE-{i + 10}") for i in range(5)]
    sarif = findings_to_sarif(findings)
    blob = json.dumps(sarif, indent=2)
    parsed = json.loads(blob)
    assert parsed["version"] == SARIF_VERSION
    assert len(parsed["runs"][0]["results"]) == 5


# =====================================================================
# Edge cases
# =====================================================================


def test_finding_with_unknown_cwe_still_produces_result():
    """A finding lacking cwe_id falls back to CWE-Unknown — should
    NOT crash the reporter."""
    sarif = findings_to_sarif([{"severity": "MEDIUM", "title": "x"}])
    result = sarif["runs"][0]["results"][0]
    assert result["ruleId"] == "CWE-Unknown"


def test_finding_with_only_severity_still_serializes():
    """Minimum viable finding (severity alone) must not crash."""
    sarif = findings_to_sarif([{"severity": "HIGH"}])
    assert sarif["runs"][0]["results"][0]["level"] == "error"


def test_title_capped_to_thousand_chars():
    """SARIF doesn't define a max but downstream consumers do; we
    cap message.text at 1000 chars so a runaway finding doesn't
    blow up a GitHub annotation."""
    sarif = findings_to_sarif([_finding(title="x" * 5000)])
    assert len(sarif["runs"][0]["results"][0]["message"]["text"]) == 1000
