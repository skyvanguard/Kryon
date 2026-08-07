"""OpenVAS get_results XML → engage.Finding mapping + applicability gate wiring."""

from __future__ import annotations

from kryon.integrations.openvas import normalizer
from kryon.integrations.openvas.normalizer import cvss_to_severity, parse_results, results_to_findings

# One CVE-bearing NVT (2 CVEs) + one CVE-less info NVT.
_RESULTS_XML = """
<get_results_response status="200" status_text="OK">
  <result id="r1">
    <name>OpenSSL Multiple Vulnerabilities</name>
    <host>10.0.0.5<hostname>web01</hostname></host>
    <port>443/tcp</port>
    <nvt oid="1.3.6.1.4.1.25623.1.0.111111">
      <name>OpenSSL Multiple Vulnerabilities</name>
      <family>SSL and TLS</family>
      <cvss_base>7.5</cvss_base>
      <refs>
        <ref type="cve" id="CVE-2021-3711"/>
        <ref type="cve" id="CVE-2021-3712"/>
        <ref type="url" id="https://openssl.org"/>
      </refs>
      <tags>summary=SSL bug|solution_type=VendorFix</tags>
      <solution type="VendorFix">Upgrade to OpenSSL 1.1.1l or later.</solution>
    </nvt>
    <threat>High</threat>
    <severity>7.5</severity>
    <qod><value>80</value><type>remote_banner</type></qod>
    <description>Installed version: 1.1.1f</description>
  </result>
  <result id="r2">
    <name>TCP timestamps</name>
    <host>10.0.0.5</host>
    <port>general/tcp</port>
    <nvt oid="1.3.6.1.4.1.25623.1.0.80091">
      <name>TCP timestamps information disclosure</name>
      <family>General</family>
      <cvss_base>2.6</cvss_base>
      <refs/>
      <tags>summary=x|solution=Disable TCP timestamps</tags>
    </nvt>
    <threat>Low</threat>
    <severity>2.6</severity>
    <qod><value>80</value></qod>
    <description>TCP timestamps enabled</description>
  </result>
</get_results_response>
""".strip()


def test_cvss_to_severity_bands():
    assert cvss_to_severity(9.1) == "CRITICAL"
    assert cvss_to_severity(7.5) == "HIGH"
    assert cvss_to_severity(5.0) == "MEDIUM"
    assert cvss_to_severity(1.0) == "LOW"
    assert cvss_to_severity(0.0) == "INFO"


def test_parse_results_extracts_fields():
    rows = parse_results(_RESULTS_XML)
    assert len(rows) == 2
    r1 = rows[0]
    assert r1["host"] == "10.0.0.5"
    assert r1["cves"] == ["CVE-2021-3711", "CVE-2021-3712"]
    assert r1["qod"] == 80
    assert r1["severity_num"] == 7.5
    assert "OpenSSL 1.1.1l" in r1["solution"]
    # CVE-less result pulls solution from tags
    r2 = rows[1]
    assert r2["cves"] == []
    assert r2["solution"] == "Disable TCP timestamps"


def test_one_finding_per_cve():
    findings = results_to_findings(_RESULTS_XML, apply_gates=False)
    # 2 CVEs from r1 + 1 CVE-less from r2 = 3 findings.
    assert len(findings) == 3
    rule_ids = {f.rule_id for f in findings}
    assert "CVE-2021-3711" in rule_ids
    assert "CVE-2021-3712" in rule_ids
    assert any(rid.startswith("OPENVAS-") for rid in rule_ids)


def test_mapping_fields():
    findings = results_to_findings(_RESULTS_XML, apply_gates=False)
    cve_f = next(f for f in findings if f.rule_id == "CVE-2021-3711")
    assert cve_f.severity == "HIGH"  # 7.5
    assert cve_f.confidence == 0.8  # QoD 80
    assert cve_f.needs_verification is True
    assert cve_f.host == "10.0.0.5"
    assert "OpenSSL 1.1.1l" in cve_f.remediation
    info_f = next(f for f in findings if f.rule_id.startswith("OPENVAS-"))
    assert info_f.severity == "LOW"  # 2.6


def test_gates_pass_keeps_all(monkeypatch):
    monkeypatch.setattr(normalizer, "is_cve_applicable_for_finding", lambda f, *, tech_stack: (True, "ok"))
    monkeypatch.setattr(normalizer, "is_finding_applicable_general", lambda f, *, tech_stack: (True, "ok"))
    findings = results_to_findings(_RESULTS_XML, tech_stack={"linux"}, apply_gates=True)
    assert len(findings) == 3


def test_cve_gate_drops_nonapplicable(monkeypatch):
    # Drop only CVE-2021-3711; general gate passes everything.
    def cve_gate(finding, *, tech_stack):
        rid = getattr(finding, "rule_id", "")
        return ("3711" not in rid, "test")

    monkeypatch.setattr(normalizer, "is_cve_applicable_for_finding", cve_gate)
    monkeypatch.setattr(normalizer, "is_finding_applicable_general", lambda f, *, tech_stack: (True, "ok"))
    findings = results_to_findings(_RESULTS_XML, tech_stack={"linux"}, apply_gates=True)
    rule_ids = {f.rule_id for f in findings}
    assert "CVE-2021-3711" not in rule_ids
    assert "CVE-2021-3712" in rule_ids
    assert len(findings) == 2
