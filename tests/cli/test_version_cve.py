"""Deterministic version→CVE→exploit correlation engine."""

from __future__ import annotations

from kryon.cli.version_cve import correlate, correlate_banner, parse_version


def _cves(banner):
    return {h.cve for h in correlate(banner)}


def test_parse_version():
    assert parse_version("Apache Tomcat/7.0.34") == (7, 0, 34)
    assert parse_version("OpenSSH_9.6p1") == (9, 6)
    assert parse_version("no version here") is None


def test_openssh_regresshion_in_range():
    assert "CVE-2024-6387" in _cves("SSH-2.0-OpenSSH_9.6p1")


def test_openssh_out_of_range():
    assert "CVE-2024-6387" not in _cves("SSH-2.0-OpenSSH_9.8p1")


def test_tomcat_ghostcat():
    assert "CVE-2020-1938" in _cves("Apache Tomcat/7.0.34")


def test_vsftpd_backdoor():
    hits = correlate("vsftpd 2.3.4")
    assert any(h.cve == "CVE-2011-2523" and h.exploit for h in hits)


def test_apache_path_traversal_exact_version():
    assert "CVE-2021-41773" in _cves("Apache/2.4.49 (Unix)")
    assert "CVE-2021-41773" not in _cves("Apache/2.4.48 (Unix)")


def test_proftpd_modcopy():
    assert "CVE-2015-3306" in _cves("ProFTPD 1.3.5")


def test_no_version_no_hits():
    assert correlate("nginx") == []


def test_product_mismatch_no_hit():
    # Tomcat CVE shouldn't match an nginx banner even if the version is in range.
    assert "CVE-2020-1938" not in _cves("nginx/7.0.34")


def test_to_findings_shape():
    out = correlate_banner("Apache Tomcat/7.0.34", "10.0.0.9", 8080)
    assert out and out[0].rule_id == "cve-2020-1938" and out[0].cwe == "CWE-1395"
    assert "exploit público" in out[0].message and "10.0.0.9" in out[0].message


def test_to_findings_are_inferred_not_ground_truth():
    """F210 — banner→CVE is inferred (spoofable banner, backported fixes).
    The uncertainty must live in the data, not just the message wording,
    so the report routes it to 'requiere verificación'."""
    out = correlate_banner("Apache Tomcat/7.0.34", "10.0.0.9", 8080)
    f = out[0]
    assert f.verification_level == "inferred"
    assert f.needs_verification is True
    assert f.confidence < 0.7


def test_inferred_finding_stays_low_after_confidence_scoring():
    """Even after the post-engagement annotate_confidence pass, a
    banner-inferred CVE must NOT get promoted to ground truth (its
    lowercase cve- rule_id must not be scored as deterministic 1.0)."""
    from kryon.scoring.confidence import annotate_confidence

    out = correlate_banner("Apache Tomcat/7.0.34", "10.0.0.9", 8080)
    annotate_confidence(out)
    assert out[0].confidence < 0.7
    assert out[0].needs_verification is True


def test_correlate_banner_graceful_on_junk():
    assert correlate_banner("", "h", 1) == []


def test_correlate_services_matches_vsftpd_on_ftp_port():
    # T4-A4: banner→CVE must fire for a NON-SSH service (the one-shots were SSH-only).
    from types import SimpleNamespace

    from kryon.cli.version_cve import correlate_services

    svc = SimpleNamespace(product="vsftpd", version="2.3.4", host="10.0.0.5", port=21)
    findings = correlate_services([svc])
    assert findings, "vsftpd 2.3.4 backdoor should be flagged"


def test_correlate_services_empty_without_version():
    from types import SimpleNamespace

    from kryon.cli.version_cve import correlate_services

    svc = SimpleNamespace(product="", version="", host="t", port=80)
    assert correlate_services([svc]) == []
