"""Tests for intelligence models."""

from kryon.intelligence.models import (
    CVEDetail,
    Finding,
    IoC,
    MITREMapping,
    Severity,
)


def test_severity_enum():
    assert Severity.CRITICAL.value == "critical"
    assert Severity.INFO.value == "info"


def test_mitre_mapping():
    m = MITREMapping(
        tactic="Discovery",
        tactic_id="TA0007",
        technique="Network Service Discovery",
        technique_id="T1046",
        confidence=0.9,
    )
    assert m.tactic_id == "TA0007"
    assert m.technique_id == "T1046"
    assert m.subtechnique is None


def test_cve_detail():
    cve = CVEDetail(cve_id="CVE-2024-12345", cvss_score=9.8, cisa_kev=True)
    assert cve.cve_id == "CVE-2024-12345"
    assert cve.exploit_available is False
    assert cve.cisa_kev is True


def test_ioc():
    ioc = IoC(type="ip", value="1.2.3.4", source="nmap", threat_score=0.5)
    assert ioc.type == "ip"
    assert ioc.threat_score == 0.5


def test_finding_auto_id():
    f1 = Finding(
        title="Open Port 22",
        description="SSH open",
        severity=Severity.LOW,
        affected_asset="192.168.1.1",
    )
    f2 = Finding(
        title="SQL Injection",
        description="SQLi found",
        severity=Severity.CRITICAL,
        affected_asset="example.com",
    )
    assert f1.id != f2.id
    assert len(f1.id) == 12
    assert f1.timestamp != ""


def test_finding_with_cve_and_mitre():
    f = Finding(
        title="Apache Struts RCE",
        description="CVE-2017-5638",
        severity=Severity.CRITICAL,
        affected_asset="10.0.0.1",
        cve=CVEDetail(cve_id="CVE-2017-5638", cvss_score=10.0),
        mitre=[
            MITREMapping(
                tactic="Initial Access",
                tactic_id="TA0001",
                technique="Exploit Public-Facing Application",
                technique_id="T1190",
                confidence=0.95,
            )
        ],
    )
    assert f.cve.cve_id == "CVE-2017-5638"
    assert len(f.mitre) == 1
    assert f.mitre[0].technique_id == "T1190"
